const { prisma } = require('../config/database');

function parseClientDateTime(value) {
  if (value === undefined || value === null || value === '') {
    return new Date();
  }
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? new Date() : d;
}

async function enrichTxn(txn) {
  let recipientName = null;
  if (txn.recipientUserId) {
    const u = await prisma.user.findUnique({ where: { id: txn.recipientUserId }, select: { name: true } });
    recipientName = u?.name || null;
  } else if (txn.recipientOrgId) {
    const org = await prisma.organization.findUnique({ where: { id: txn.recipientOrgId }, select: { name: true } });
    recipientName = org?.name || null;
  }
  let fundName = null;
  if (txn.orgFundId) {
    const fundTxn = await prisma.transaction.findUnique({ where: { id: txn.orgFundId } });
    if (fundTxn) {
      if (fundTxn.linkedTransactionId) {
        const orgTxn = await prisma.transaction.findUnique({ where: { id: fundTxn.linkedTransactionId }, include: { book: { include: { organization: { select: { name: true } } } } } });
        fundName = orgTxn?.book?.organization?.name || null;
      }
    } else {
      const fundBook = await prisma.book.findUnique({ where: { id: txn.orgFundId }, include: { organization: true } });
      fundName = fundBook?.organization?.name || null;
    }
  }
  if (!fundName && txn.linkedTransactionId) {
    const linkedTxn = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId }, include: { book: { include: { organization: { select: { name: true } } } } } });
    fundName = linkedTxn?.book?.organization?.name || null;
  }
  let creatorName = null;
  let creatorAvatarUrl = null;
  if (txn.createdById) {
    const u = await prisma.user.findUnique({ where: { id: txn.createdById }, select: { name: true, avatarUrl: true } });
    creatorName = u?.name || null;
    creatorAvatarUrl = u?.avatarUrl || null;
  }

  let approverName = null;
  let approverAvatarUrl = null;
  let rejecterName = null;
  let rejecterAvatarUrl = null;

  if (txn.updateHistory && Array.isArray(txn.updateHistory)) {
    const approveAction = [...txn.updateHistory].reverse().find(h => h && h.action === 'approve');
    if (approveAction) {
      approverName = approveAction.userName || 'Unknown';
      if (approveAction.userId) {
        const u = await prisma.user.findUnique({ where: { id: approveAction.userId }, select: { avatarUrl: true } });
        approverAvatarUrl = u?.avatarUrl || null;
      }
    }
    const rejectAction = [...txn.updateHistory].reverse().find(h => h && h.action === 'reject');
    if (rejectAction) {
      rejecterName = rejectAction.userName || 'Unknown';
      if (rejectAction.userId) {
        const u = await prisma.user.findUnique({ where: { id: rejectAction.userId }, select: { avatarUrl: true } });
        rejecterAvatarUrl = u?.avatarUrl || null;
      }
    }
  }

  return {
    ...txn,
    recipientName,
    fundName,
    creatorName,
    creatorAvatarUrl,
    approverName,
    approverAvatarUrl,
    rejecterName,
    rejecterAvatarUrl,
    chainId: txn.chainId,
    chainType: txn.chainType,
    isLiability: txn.isLiability,
    adjustedAmount: txn.adjustedAmount
  };
}

module.exports = { parseClientDateTime, enrichTxn };
