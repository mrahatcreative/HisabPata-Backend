const { prisma } = require('../../../config/database');
const { broadcast, broadcastToUser, broadcastToUsers } = require('../../../websocket');
const { enrichTxn } = require('../../../helpers/enrichTxn');

module.exports = async (ctx) => {
  const { book, parsedAmount, txnClientRef, txnDateTime, computedFundType, deps, req, res } = ctx;
  const { checkApprovalBypass, hasAdminOrEditorAccess, checkPermission, createNotification, getOrgAdminUserIds, maybeMirrorOrgTxnToCreatorPersonal, getChainRemainingBalance } = deps;
  const { note, contact, fromLocation, toLocation, imageUrl, recipientUserId, bookId } = req.body;
  const orgFundId = req.body.orgFundId || req.body.fundBookId;

  const recipientMembership = await prisma.organizationMember.findFirst({
    where: { userId: recipientUserId, organization: { isPersonal: true } },
    include: { organization: { include: { books: { where: { isDefault: true } } } } }
  });
  if (!recipientMembership || recipientMembership.organization.books.length === 0) {
    return res.status(400).json({ error: 'Recipient has no personal book' });
  }
  const recipientBook = recipientMembership.organization.books[0];

  let bypassOrgApproval = await checkApprovalBypass(book.organizationId, req.user.id);
  const isSelfSend = recipientUserId === req.user.id;
  const initialStatus = (isSelfSend && bypassOrgApproval) ? 'approved' : 'pending';

  let chainId = null;
  let chainType = null;
  let fundTxnParent = null;
  if (orgFundId) {
    fundTxnParent = await prisma.transaction.findUnique({ where: { id: orgFundId } });
    if (fundTxnParent) {
      chainId = fundTxnParent.chainId;
      if (!chainId && fundTxnParent.linkedTransactionId) {
        const linkedFund = await prisma.transaction.findUnique({ where: { id: fundTxnParent.linkedTransactionId } });
        chainId = linkedFund?.chainId;
      }
      const { remaining } = await getChainRemainingBalance(orgFundId);
      if (parsedAmount > remaining) {
        return res.status(400).json({ error: `Insufficient fund balance: requested ${parsedAmount}, remaining ${remaining}` });
      }
      chainType = 'split';
    }
  }

  let sourceNote = note;
  if (orgFundId && fundTxnParent) {
    const senderName = req.user.name || 'A user';
    const recipientUser = await prisma.user.findUnique({ where: { id: recipientUserId }, select: { name: true } });
    const recipientName = recipientUser?.name || 'another member';
    const transferInfo = `Transferred to ${recipientName} from ${senderName}`;
    sourceNote = note ? `${note} (${transferInfo})` : transferInfo;
  }

  const result = await prisma.$transaction(async (prisma) => {
    const sourceTxn = await prisma.transaction.create({
      data: { bookId, amount: parsedAmount, type: 'expense', note: sourceNote, category: 'Send', contact, recipientUserId, fundType: computedFundType, fromLocation, toLocation, createdById: req.user.id, reconStatus: initialStatus, imageUrl, chainId, chainType, orgFundId, clientRef: txnClientRef, dateTime: txnDateTime }
    });
    const recipientTxn = await prisma.transaction.create({
      data: { bookId: recipientBook.id, amount: parsedAmount, type: 'income', note: note || '', category: 'Send', contact, recipientUserId: req.user.id, linkedTransactionId: null, fundType: computedFundType, fromLocation, toLocation, createdById: req.user.id, reconStatus: initialStatus, chainId, chainType, dateTime: txnDateTime }
    });
    await prisma.book.update({ where: { id: bookId }, data: { balance: { decrement: parsedAmount } } });
    if (initialStatus === 'approved') {
      await prisma.book.update({ where: { id: recipientBook.id }, data: { balance: { increment: parsedAmount } } });
    }
    await prisma.transaction.update({ where: { id: sourceTxn.id }, data: { linkedTransactionId: recipientTxn.id } });
    await prisma.transaction.update({ where: { id: recipientTxn.id }, data: { linkedTransactionId: sourceTxn.id } });
    await maybeMirrorOrgTxnToCreatorPersonal(prisma, {
      orgTxn: sourceTxn,
      orgBook: book,
      userId: req.user.id,
      txnClientRef,
      skipMirror: isSelfSend
    });
    return sourceTxn;
  });

  broadcast({ type: "data_changed" });
  const enriched = await enrichTxn(result);

  const adminIds = await getOrgAdminUserIds(book.organizationId);
  const senderName = req.user.name || 'A user';
  const recipientName = enriched.recipientName || 'another member';

  if (chainType === 'split' && fundTxnParent) {
    const { remaining } = await getChainRemainingBalance(orgFundId);
    const bnMsg = `${senderName}-কে দেওয়া ${fundTxnParent.amount} টাকা থেকে ${parsedAmount} টাকা এখন ${recipientName}-এর কাছে ট্রান্সফার করা হয়েছে। ${senderName}-এর অবশিষ্টাংশ: ${remaining} টাকা।`;
    const enMsg = `${parsedAmount} Tk from the ${fundTxnParent.amount} Tk given to ${senderName} has been transferred to ${recipientName}. ${senderName}'s remaining: ${remaining} Tk.`;
    broadcastToUsers(adminIds, { type: "chain_split", message: { bn: bnMsg, en: enMsg }, transaction: enriched });
  } else if (chainType === 'deficit') {
    const deficitAmt = parsedAmount;
    const bnMsg = `${senderName} ${enriched.fundName || 'ফান্ড'} থেকে ${recipientName}-কে ${deficitAmt} টাকা অগ্রিম (Advance) পাঠিয়েছে। ${senderName}-এর বর্তমান ফান্ড ব্যালেন্স: -${deficitAmt} টাকা।`;
    const enMsg = `${senderName} sent ${deficitAmt} Tk as an advance from ${enriched.fundName || 'the fund'} to ${recipientName}. ${senderName}'s current fund balance: -${deficitAmt} Tk.`;
    broadcastToUsers(adminIds, { type: "deficit_send", message: { bn: bnMsg, en: enMsg }, transaction: enriched });
  }

  if (initialStatus !== 'approved') {
    broadcastToUser(recipientUserId, { type: "pending_send_received", transaction: enriched });
    await createNotification(recipientUserId, 'SEND_RECEIVED', 'টাকা পাঠানো হয়েছে', `${req.user.name || 'কেউ'} ${parsedAmount} টাকা পাঠিয়েছে।`, result?.id, null);
  }
  return res.status(201).json({ transaction: enriched, isHandshake: true, approvalBypassed: bypassOrgApproval });
};
