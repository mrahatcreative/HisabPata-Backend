const { prisma } = require('../../config/database');
const { findFundVoucherPairedTxn } = require('../mirror');
const { parsePendingData, reverseTxnBalanceForRemoval } = require('../misc');

const getCounterpartLegsForChangeDelete = async (txn, book, txClient = prisma) => {
  if (txn.chainId) {
    const chainTxns = await txClient.transaction.findMany({
      where: { chainId: txn.chainId, id: { not: txn.id } }
    });
    if (chainTxns.length > 0) return chainTxns;
  }

  const legs = [];
  if (txn.linkedTransactionId) {
    const linked = await txClient.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
    if (linked) legs.push(linked);
    
    // Also check if this transaction IS the linkedTransactionId of another
    const inverseLinked = await txClient.transaction.findFirst({ where: { linkedTransactionId: txn.id } });
    if (inverseLinked && !legs.some(l => l.id === inverseLinked.id)) {
      legs.push(inverseLinked);
    }
  } else {
    const inverseLinked = await txClient.transaction.findFirst({ where: { linkedTransactionId: txn.id } });
    if (inverseLinked) legs.push(inverseLinked);
  }

  const paired = await findFundVoucherPairedTxn(txn, book, txClient);
  if (paired && paired.id !== txn.id && !legs.some((l) => l.id === paired.id)) {
    legs.push(paired);
  }
  return legs;
};

const syncCounterpartLegsForChangeDelete = async (tx, txn, book, opts, requesterId = null) => {
  const {
    pendingAction,
    pendingData,
    fieldUpdates = {},
    historyEntry = null,
    reverseBalanceOnRequest = false,
    keepReconStatus = false
  } = opts;
  const legs = await getCounterpartLegsForChangeDelete(txn, book, tx);
  for (const leg of legs) {
    const legBook = await tx.book.findUnique({ where: { id: leg.bookId } });
    if (!legBook) continue;

    if (requesterId && legBook.organizationId) {
      const legOrg = await tx.organization.findUnique({ where: { id: legBook.organizationId }, select: { isPersonal: true } });
      if (legOrg && !legOrg.isPersonal) {
        const membership = await tx.organizationMember.findUnique({
          where: { userId_organizationId: { userId: requesterId, organizationId: legBook.organizationId } }
        });
        if (!membership || membership.status !== 'active') continue;
      }
    }

    if (reverseBalanceOnRequest) {
      const balanceAdj = leg.type === 'expense' ? leg.amount : -leg.amount;
      await tx.book.update({ where: { id: legBook.id }, data: { balance: { increment: balanceAdj } } });
    } else if (fieldUpdates.amount !== undefined || (fieldUpdates.reconStatus === 'pending' && leg.reconStatus === 'rejected')) {
      // Direct edit amount change or retry of rejected leg: adjust balance
      const newAmount = fieldUpdates.amount !== undefined ? fieldUpdates.amount : leg.amount;
      let legDelta = 0;
      
      if (leg.reconStatus === 'rejected' && leg.category !== 'Send') {
        // If a non-Send leg was rejected, the balance was fully reversed previously. Apply the full new amount.
        legDelta = leg.type === 'expense' ? -newAmount : newAmount;
      } else if (fieldUpdates.amount !== undefined && fieldUpdates.amount !== leg.amount) {
        // Just an amount change (or a retry of a Send transaction which was never reversed)
        legDelta = leg.type === 'expense' ? (leg.amount - newAmount) : (newAmount - leg.amount);
      }

      if (legDelta !== 0) {
        await tx.book.update({ where: { id: legBook.id }, data: { balance: { increment: legDelta } } });
      }
    }

    const data = { ...fieldUpdates };
    if (pendingAction) {
      if (!keepReconStatus) {
        data.reconStatus = 'pending';
      }
      data.pendingAction = pendingAction;
      data.pendingData = pendingData;
    }
    if (historyEntry) {
      data.updateHistory = [...(leg.updateHistory || []), historyEntry];
    }

    await tx.transaction.update({ where: { id: leg.id }, data });
  }
};

const deleteCounterpartLegsForChangeDelete = async (tx, txn, book) => {
  const legs = await getCounterpartLegsForChangeDelete(txn, book, tx);
  for (const leg of legs) {
    let adj = reverseTxnBalanceForRemoval(leg);
    if (leg.reconStatus === 'rejected' && leg.category !== 'Send') {
      adj = 0;
    }
    if (adj !== 0) {
      await tx.book.update({
        where: { id: leg.bookId },
        data: { balance: { increment: adj } }
      });
    }
    await tx.transaction.delete({ where: { id: leg.id } });
  }
};

const finalizeCounterpartLegsOnEditApprove = async (tx, txn, book, approveHistoryEntry) => {
  const legs = await getCounterpartLegsForChangeDelete(txn, book, tx);
  const source = await tx.transaction.findUnique({ where: { id: txn.id } });
  if (!source) return;

  for (const leg of legs) {
    const cur = await tx.transaction.findUnique({
      where: { id: leg.id },
      select: { version: true, updateHistory: true, amount: true, type: true, bookId: true, pendingData: true }
    });
    if (!cur) continue;

    const syncFields = {
      amount: source.amount,
      note: source.note,
      category: source.category,
      reconStatus: 'approved',
      pendingAction: null,
      pendingData: null,
      version: { increment: 1 },
      updateHistory: [...(cur.updateHistory || []), approveHistoryEntry]
    };
    await tx.transaction.updateMany({
      where: { id: leg.id, version: cur.version },
      data: syncFields
    });

    const legPd = parsePendingData(cur.pendingData);
    const legOldAmount = (legPd.oldAmount != null ? Number(legPd.oldAmount) : source.amount);
    const legDelta = cur.type === 'expense'
      ? (legOldAmount - source.amount)
      : (source.amount - legOldAmount);
    if (legDelta !== 0) {
      await tx.book.update({
        where: { id: leg.bookId },
        data: { balance: { increment: legDelta } }
      });
    }
  }
};

module.exports = {
  getCounterpartLegsForChangeDelete,
  syncCounterpartLegsForChangeDelete,
  deleteCounterpartLegsForChangeDelete,
  finalizeCounterpartLegsOnEditApprove,
};
