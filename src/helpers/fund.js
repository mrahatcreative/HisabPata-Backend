const { prisma } = require('../config/database');

const resolveOrgDisbursementOrgTxn = async (txn, book) => {
  let resolvedBook = book;
  if (!resolvedBook?.organization) {
    resolvedBook = await prisma.book.findUnique({
      where: { id: txn.bookId },
      include: { organization: true }
    });
  }
  if (!resolvedBook) return null;

  if (!resolvedBook.organization?.isPersonal && txn.type === 'expense' && txn.category === 'Send') {
    return { orgTxn: txn, orgBook: resolvedBook };
  }
  if (resolvedBook.organization?.isPersonal && txn.type === 'income' && txn.category === 'Send' && txn.linkedTransactionId) {
    const linked = await prisma.transaction.findUnique({
      where: { id: txn.linkedTransactionId },
      include: { book: { include: { organization: true } } }
    });
    if (linked?.type === 'expense' && linked?.category === 'Send' && !linked.book?.organization?.isPersonal) {
      return { orgTxn: linked, orgBook: linked.book };
    }
  }
  return null;
};

const getFundSendChain = async (txn, txClient = prisma) => {
  if (txn.chainType === 'fund_send' && txn.chainId) {
    return txClient.transaction.findMany({ where: { chainId: txn.chainId } });
  }
  return null;
};

const rejectFundSendChain = async (tx, txn, rejectHistoryEntry) => {
  const chain = await getFundSendChain(txn, tx);
  if (!chain) return false;
  for (const ct of chain) {
    if (ct.reconStatus === 'rejected') continue;
    const cur = await tx.transaction.findUnique({
      where: { id: ct.id },
      select: { version: true, updateHistory: true }
    });
    if (!cur) throw new Error('Chain transaction not found');
    const upd = await tx.transaction.updateMany({
      where: { id: ct.id, version: cur.version },
      data: {
        reconStatus: 'rejected',
        pendingAction: null,
        pendingData: null,
        counterProposedAmount: null,
        counterProposedBy: null,
        version: { increment: 1 },
        updateHistory: [...(cur.updateHistory || []), rejectHistoryEntry]
      }
    });
    if (upd.count === 0) throw new Error('Concurrency conflict on fund_send reject');
    if (ct.reconStatus === 'approved') {
      const balanceAdj = ct.type === 'expense' ? ct.amount : -ct.amount;
      await tx.book.update({
        where: { id: ct.bookId },
        data: { balance: { increment: balanceAdj } }
      });
    }
  }
  return true;
};

const resolveFundSendChainParts = (chain) => {
  const recipientTxn = chain.find(t => t.type === 'income');
  const fundOrgTxn = chain.find(t => t.type === 'expense' && t.bookId === t.orgFundId);
  const personalTxn = chain.find(t => t.type === 'expense' && t.id !== fundOrgTxn?.id);
  return { personalTxn, fundOrgTxn, recipientTxn };
};

const updateFundSendTxnStatus = async (tx, t, status, historyEntry, extraData = {}) => {
  const cur = await tx.transaction.findUnique({
    where: { id: t.id },
    select: { version: true, updateHistory: true }
  });
  if (!cur) throw new Error('Chain transaction not found');
  const data = {
    reconStatus: status,
    version: { increment: 1 },
    ...extraData
  };
  if (historyEntry) {
    data.updateHistory = [...(cur.updateHistory || []), historyEntry];
  }
  const upd = await tx.transaction.updateMany({
    where: { id: t.id, version: cur.version },
    data
  });
  if (upd.count === 0) throw new Error(`Concurrency conflict on fund_send update ${t.id}`);
};

const approveFundSendOrg = async (tx, txn, approveHistoryEntry) => {
  const chain = await getFundSendChain(txn, tx);
  if (!chain) return null;
  const { personalTxn, fundOrgTxn, recipientTxn } = resolveFundSendChainParts(chain);
  const clearCounter = { counterProposedAmount: null, counterProposedBy: null };

  if (recipientTxn?.reconStatus === 'pending' || recipientTxn?.reconStatus === 'pending_org') {
    for (const t of chain) {
      await updateFundSendTxnStatus(tx, t, 'approved', approveHistoryEntry, clearCounter);
    }
    if (recipientTxn && !recipientTxn.isLiability) {
      await tx.book.update({
        where: { id: recipientTxn.bookId },
        data: { balance: { increment: recipientTxn.amount } }
      });
    }
    return { final: true };
  }

  for (const t of [personalTxn, fundOrgTxn, recipientTxn]) {
    if (!t) continue;
    await updateFundSendTxnStatus(tx, t, 'pending', approveHistoryEntry, clearCounter);
  }
  return { final: false };
};

const approveFundSendRecipient = async (tx, txn, approveHistoryEntry) => {
  const chain = await getFundSendChain(txn, tx);
  if (!chain) return null;
  const { personalTxn, fundOrgTxn, recipientTxn } = resolveFundSendChainParts(chain);
  const clearCounter = { counterProposedAmount: null, counterProposedBy: null };
  const orgStillPending =
    personalTxn?.reconStatus === 'pending' || personalTxn?.reconStatus === 'pending_org' ||
    fundOrgTxn?.reconStatus === 'pending' || fundOrgTxn?.reconStatus === 'pending_org';

  if (orgStillPending && recipientTxn) {
    await updateFundSendTxnStatus(tx, recipientTxn, 'pending', approveHistoryEntry, clearCounter);
    return { final: false };
  }

  for (const t of chain) {
    await updateFundSendTxnStatus(tx, t, 'approved', approveHistoryEntry, clearCounter);
  }
  if (recipientTxn && !recipientTxn.isLiability) {
    await tx.book.update({
      where: { id: recipientTxn.bookId },
      data: { balance: { increment: recipientTxn.amount } }
    });
  }
  return { final: true };
};

const fundSendRetryStatuses = (bypassOrgApproval, isSelfSend) => {
  if (isSelfSend && bypassOrgApproval) {
    return { personal: 'approved', fundOrg: 'approved', recipient: 'approved' };
  }
  return { personal: 'pending', fundOrg: 'pending', recipient: 'pending' };
};

async function updateTxnWithVersion(txnId, expectedVersion, data, prismaClient) {
  const client = prismaClient || prisma;
  const result = await client.transaction.updateMany({
    where: { id: txnId, version: expectedVersion },
    data: { ...data, version: { increment: 1 } }
  });
  if (result.count === 0) {
    const current = await prisma.transaction.findUnique({ where: { id: txnId }, select: { version: true, reconStatus: true } });
    if (!current) throw new Error('Transaction not found');
    throw new Error(`Concurrency conflict: expected version ${expectedVersion}, current version ${current.version}, status ${current.reconStatus}`);
  }
  return client.transaction.findUnique({ where: { id: txnId } });
}

module.exports = { resolveOrgDisbursementOrgTxn, getFundSendChain, rejectFundSendChain, resolveFundSendChainParts, updateFundSendTxnStatus, approveFundSendOrg, approveFundSendRecipient, fundSendRetryStatuses, updateTxnWithVersion };
