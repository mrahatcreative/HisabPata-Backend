const { prisma } = require('../../../config/database');
const { broadcast, broadcastToUser, broadcastToUsers } = require('../../../websocket');
const { enrichTxn } = require('../../../helpers/enrichTxn');

module.exports = async (ctx) => {
  const { book, parsedAmount, txnClientRef, txnDateTime, computedFundType, deps, req, res } = ctx;
  const { checkApprovalBypass, hasAdminOrEditorAccess, checkPermission, createNotification, getOrgAdminUserIds } = deps;
  const { note, contact, fromLocation, toLocation, imageUrl, recipientOrgId, bookId } = req.body;

  const recipientBook = await prisma.book.findFirst({
    where: { organizationId: recipientOrgId, isDefault: true }
  });
  if (!recipientBook) {
    return res.status(400).json({ error: { bn: 'প্রাপক সংগঠনের কোনো ডিফল্ট বই নেই।', en: 'Recipient organization has no default book' } });
  }

  const bypassSourceOrgApproval = await checkApprovalBypass(book.organizationId, req.user.id);
  const bypassRecipientOrgApproval = await checkApprovalBypass(recipientOrgId, req.user.id);

  const initialStatus =
    bypassSourceOrgApproval && bypassRecipientOrgApproval ? 'approved' : 'pending';

  const result = await prisma.$transaction(async (prisma) => {
    const sourceTxn = await prisma.transaction.create({
      data: {
        bookId,
        amount: parsedAmount,
        type: 'expense',
        note: note || 'Transfer to organization',
        category: 'Send',
        contact,
        recipientOrgId,
        fundType: computedFundType,
        fromLocation,
        toLocation,
        createdById: req.user.id,
        reconStatus: initialStatus,
        imageUrl,
        clientRef: txnClientRef,
        dateTime: txnDateTime
      }
    });
    const recipientTxn = await prisma.transaction.create({
      data: {
        bookId: recipientBook.id,
        amount: parsedAmount,
        type: 'income',
        note: note || '',
        category: 'Send',
        contact,
        recipientOrgId: book.organizationId,
        fundType: computedFundType,
        fromLocation,
        toLocation,
        createdById: req.user.id,
        reconStatus: initialStatus,
        imageUrl,
        clientRef: txnClientRef,
        dateTime: txnDateTime
      }
    });

    await prisma.book.update({ where: { id: bookId }, data: { balance: { decrement: parsedAmount } } });
    await prisma.book.update({ where: { id: recipientBook.id }, data: { balance: { increment: parsedAmount } } });
    await prisma.transaction.update({ where: { id: sourceTxn.id }, data: { linkedTransactionId: recipientTxn.id } });
    await prisma.transaction.update({ where: { id: recipientTxn.id }, data: { linkedTransactionId: sourceTxn.id } });
    return sourceTxn;
  });

  broadcast({ type: "data_changed" });
  const enriched = await enrichTxn(result);

  if (initialStatus === 'pending') {
    const recipientAdmins = await prisma.organizationMember.findMany({
      where: { organizationId: recipientOrgId, status: 'active', OR: [{ role: 'admin' }, { permissions: { has: 'edit_all' } }] },
      select: { userId: true }
    });
    const adminIds = recipientAdmins.map(a => a.userId);
    broadcastToUsers(adminIds, { type: "pending_send_received", transaction: enriched });
    for (const uid of adminIds) {
      await createNotification(uid, 'SEND_RECEIVED', 'টাকা পাঠানো হয়েছে', `${req.user.name || 'কেউ'} ${parsedAmount} টাকা পাঠিয়েছে।`, enriched?.id, recipientOrgId);
    }
  }

  return res.status(201).json({ transaction: enriched, isHandshake: true, approvalBypassed: bypassSourceOrgApproval && bypassRecipientOrgApproval });
};
