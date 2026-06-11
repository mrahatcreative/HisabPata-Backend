const { prisma } = require('../config/database');
const { broadcastToUser } = require('../websocket');
const { sendPushNotification } = require('../services/fcm');

const parsePendingData = (pendingData) => {
  if (!pendingData) return {};
  return typeof pendingData === 'string' ? JSON.parse(pendingData) : pendingData;
};

const createNotification = async (userId, type, title, message, relatedTransactionId, relatedOrgId) => {
  try {
    const notif = await prisma.notification.create({
      data: {
        userId,
        type,
        title: title || '',
        message: message || '',
        relatedTransactionId: relatedTransactionId || null,
        relatedOrgId: relatedOrgId || null,
      }
    });
    broadcastToUser(userId, { type: 'new_notification', notification: notif });

    const pref = await prisma.notificationPreference.findUnique({
      where: { userId_type: { userId, type } }
    });
    if (!pref || pref.pushEnabled !== false) {
      await sendPushNotification(userId, title || type, message || '', {
        notificationId: notif.id,
        type,
        relatedTransactionId: relatedTransactionId || '',
        relatedOrgId: relatedOrgId || '',
      });
    }

    return notif;
  } catch (e) {
    console.error('Failed to create notification:', e);
    return null;
  }
};

const getOrgAdminUserIds = async (orgId) => {
  const admins = await prisma.organizationMember.findMany({
    where: { organizationId: orgId, role: 'admin', status: 'active' },
    select: { userId: true }
  });
  return admins.map(a => a.userId);
};

const reverseTxnBalanceForRemoval = (txn) => {
  if (txn.type === 'expense') return txn.amount;
  if (txn.type === 'income') return -txn.amount;
  return 0;
};

const applyTxnBalanceForAddition = (txn) => {
  if (txn.type === 'expense') return -txn.amount;
  if (txn.type === 'income') return txn.amount;
  return 0;
};

const recalculateBookBalance = async (bookId) => {
  try {
    const [incomeAgg, expenseAgg] = await Promise.all([
      prisma.transaction.aggregate({
        where: { bookId, type: 'income', reconStatus: { in: ['approved', 'FROZEN'] } },
        _sum: { amount: true }
      }),
      prisma.transaction.aggregate({
        where: { bookId, type: 'expense', reconStatus: { in: ['approved', 'FROZEN'] } },
        _sum: { amount: true }
      })
    ]);
    const totalIncome = incomeAgg._sum.amount || 0;
    const totalExpense = expenseAgg._sum.amount || 0;
    const calculatedBalance = totalIncome - totalExpense;
    await prisma.book.update({ where: { id: bookId }, data: { balance: calculatedBalance } });
    return calculatedBalance;
  } catch (err) {
    console.error(`[BALANCE_RECALC_ERROR] bookId=${bookId}:`, err.message);
    return null;
  }
};

const generateChainId = () => {
  return 'chain_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2, 10);
};

const getChainRemainingBalance = async (orgFundId) => {
  const parentTxn = await prisma.transaction.findUnique({ where: { id: orgFundId } });
  if (!parentTxn) return { remaining: 0, parentAmount: 0, splitTotal: 0 };
  let chainId = parentTxn.chainId;
  if (!chainId && parentTxn.linkedTransactionId) {
    const linked = await prisma.transaction.findUnique({ where: { id: parentTxn.linkedTransactionId } });
    chainId = linked?.chainId;
  }
  if (!chainId) return { remaining: parentTxn.amount, parentAmount: parentTxn.amount, splitTotal: 0 };
  const chainTxns = await prisma.transaction.findMany({ where: { chainId } });
  const parentAmount = chainTxns.filter(t => t.chainType === 'parent').reduce((s, t) => s + t.amount, 0) || parentTxn.amount;
  const splitTotal = chainTxns.filter(t => t.chainType === 'split').reduce((s, t) => s + t.amount, 0);
  const remaining = Math.max(0, parentAmount - splitTotal);
  return { remaining, parentAmount, splitTotal };
};

const resolveApprovalOrgId = async (txn, book) => {
  if (txn.orgFundId) {
    const fundBook = await prisma.book.findUnique({
      where: { id: txn.orgFundId },
      select: { id: true, organizationId: true }
    });
    if (fundBook && fundBook.id !== book.id) {
      return fundBook.organizationId;
    }
    const fundTxn = await prisma.transaction.findUnique({
      where: { id: txn.orgFundId },
      select: { bookId: true }
    });
    if (fundTxn) {
      const fundTxnBook = await prisma.book.findUnique({
        where: { id: fundTxn.bookId },
        select: { organizationId: true }
      });
      if (fundTxnBook) return fundTxnBook.organizationId;
    }
  }
  return book.organizationId;
};

module.exports = { parsePendingData, createNotification, getOrgAdminUserIds, reverseTxnBalanceForRemoval, applyTxnBalanceForAddition, recalculateBookBalance, generateChainId, getChainRemainingBalance, resolveApprovalOrgId };
