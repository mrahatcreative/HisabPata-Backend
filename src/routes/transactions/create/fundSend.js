const { prisma } = require('../../../config/database');
const { broadcast, broadcastToUser, broadcastToUsers } = require('../../../websocket');
const { enrichTxn } = require('../../../helpers/enrichTxn');

module.exports = async (ctx) => {
  const { book, parsedAmount, txnClientRef, txnDateTime, computedFundType, deps, req, res } = ctx;
  const { checkApprovalBypass, hasAdminOrEditorAccess, checkPermission, createNotification, getOrgAdminUserIds, maybeMirrorOrgTxnToCreatorPersonal, getChainRemainingBalance, generateChainId, fundSendRetryStatuses } = deps;
  const { note, contact, fromLocation, toLocation, imageUrl, recipientUserId, recipientOrgId, bookId } = req.body;
  const orgFundId = req.body.orgFundId || req.body.fundBookId;

  const fundBook = await prisma.book.findUnique({
    where: { id: orgFundId },
    include: { organization: { select: { isPersonal: true, id: true } } }
  });
  const isFundOrgBook = fundBook && !fundBook.organization.isPersonal && fundBook.id !== bookId;

  if (!isFundOrgBook) {
    return res.status(400).json({ error: 'Invalid fund book' });
  }

  if (recipientOrgId && fundBook.organizationId === recipientOrgId) {
    return res.status(400).json({ error: 'Cannot send money from an organization fund to the same organization.' });
  }

  let recipientBook = null;
  if (recipientUserId) {
    const recipientMembership = await prisma.organizationMember.findFirst({
      where: { userId: recipientUserId, organization: { isPersonal: true } },
      include: { organization: { include: { books: { where: { isDefault: true } } } } }
    });
    if (!recipientMembership || recipientMembership.organization.books.length === 0) {
      return res.status(400).json({ error: 'Recipient has no personal book' });
    }
    recipientBook = recipientMembership.organization.books[0];
  } else {
    recipientBook = await prisma.book.findFirst({
      where: { organizationId: recipientOrgId, isDefault: true }
    });
    if (!recipientBook) {
      return res.status(400).json({ error: 'Recipient organization has no default book' });
    }
  }

  const bypassFundOrgApproval = await checkApprovalBypass(fundBook.organizationId, req.user.id);
  const isSelfSend = recipientUserId === req.user.id;
  const retryStatuses = fundSendRetryStatuses(bypassFundOrgApproval, isSelfSend);
  const personalStatus = retryStatuses.personal;
  const fundOrgStatus = retryStatuses.fundOrg;
  const recipientStatus = retryStatuses.recipient;

  const chainId = generateChainId();
  const chainType = 'fund_send';

  const result = await prisma.$transaction(async (prisma) => {
    const personalTxn = await prisma.transaction.create({
      data: {
        bookId,
        amount: parsedAmount,
        type: 'expense',
        note: note || '',
        category: 'Send',
        contact,
        recipientUserId: recipientUserId || null,
        recipientOrgId: recipientOrgId || null,
        orgFundId: fundBook.id,
        fundType: computedFundType,
        fromLocation,
        toLocation,
        createdById: req.user.id,
        reconStatus: personalStatus,
        imageUrl,
        chainId,
        chainType,
        clientRef: txnClientRef,
        dateTime: txnDateTime
      }
    });

    const fundOrgTxn = await prisma.transaction.create({
      data: {
        bookId: fundBook.id,
        amount: parsedAmount,
        type: 'expense',
        note: note || '',
        category: 'Send',
        contact,
        recipientUserId: recipientUserId || null,
        recipientOrgId: recipientOrgId || null,
        orgFundId: fundBook.id,
        fundType: computedFundType,
        fromLocation,
        toLocation,
        createdById: req.user.id,
        reconStatus: fundOrgStatus,
        imageUrl,
        chainId,
        chainType,
        clientRef: txnClientRef,
        linkedTransactionId: personalTxn.id,
        isLiability: true,
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
        recipientUserId: recipientUserId ? req.user.id : null,
        recipientOrgId: recipientOrgId ? fundBook.organizationId : null,
        orgFundId: fundBook.id,
        fundType: computedFundType,
        fromLocation,
        toLocation,
        createdById: req.user.id,
        reconStatus: recipientStatus,
        imageUrl,
        chainId,
        chainType,
        clientRef: txnClientRef,
        dateTime: txnDateTime
      }
    });

    await prisma.book.update({ where: { id: bookId }, data: { balance: { decrement: parsedAmount } } });
    await prisma.book.update({ where: { id: fundBook.id }, data: { balance: { decrement: parsedAmount } } });
    await prisma.book.update({ where: { id: recipientBook.id }, data: { balance: { increment: parsedAmount } } });

    await prisma.transaction.update({
      where: { id: personalTxn.id },
      data: { linkedTransactionId: recipientTxn.id }
    });
    await prisma.transaction.update({
      where: { id: recipientTxn.id },
      data: { linkedTransactionId: personalTxn.id }
    });

    return { personalTxn, fundOrgTxn, recipientTxn };
  });

  broadcast({ type: 'data_changed' });
  const enrichedPersonal = await enrichTxn(result.personalTxn);
  const enrichedFund = await enrichTxn(result.fundOrgTxn);
  const enrichedRecipient = await enrichTxn(result.recipientTxn);

  if (recipientStatus === 'pending' && !isSelfSend) {
    if (recipientUserId) {
      broadcastToUser(recipientUserId, { type: 'pending_send_received', transaction: enrichedRecipient });
      await createNotification(recipientUserId, 'SEND_RECEIVED', 'টাকা পাঠানো হয়েছে', `${req.user.name || 'কেউ'} ${parsedAmount} টাকা পাঠিয়েছে।`, result?.personalTxn?.id, null);
    } else if (recipientOrgId) {
      const recipientAdmins = await prisma.organizationMember.findMany({
        where: {
          organizationId: recipientOrgId,
          status: 'active',
          OR: [{ role: 'admin' }, { permissions: { has: 'edit_all' } }]
        },
        select: { userId: true }
      });
      const adminIds = recipientAdmins.map(a => a.userId);
      broadcastToUsers(adminIds, {
        type: 'pending_send_received',
        transaction: enrichedRecipient
      });
      for (const uid of adminIds) {
        await createNotification(uid, 'SEND_RECEIVED', 'টাকা পাঠানো হয়েছে', `${req.user.name || 'কেউ'} ${parsedAmount} টাকা পাঠিয়েছে।`, result?.personalTxn?.id, recipientOrgId);
      }
    }
  }

  return res.status(201).json({
    transaction: enrichedPersonal,
    fundOrgTxn: enrichedFund,
    recipientTxn: enrichedRecipient,
    isHandshake: true,
    approvalBypassed: bypassFundOrgApproval
  });
};
