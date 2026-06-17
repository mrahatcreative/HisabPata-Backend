const { prisma } = require('../../../config/database');
const { getCounterpartLegsForChangeDelete } = require('../../../helpers/index');
const { broadcast } = require('../../../websocket');

const handleCancel = async (ctx) => {
  const { txn, txnId, book, res, deps } = ctx;
  const { createNotification, parsePendingData } = deps;

  if (!txn.pendingAction) {
    return res.status(400).json({ error: 'There is no pending action to cancel on this transaction' });
  }

  const pd = txn.pendingData;
  if (!pd || !book) {
    return res.status(400).json({ error: 'Missing pending data or book' });
  }

  const pdObj = parsePendingData(pd);
  await prisma.$transaction(async (tx) => {
    let balanceDelta = 0;
    if (txn.pendingAction === 'delete') {
      const isSend = txn.category === 'Send';
      if (!isSend) {
        balanceDelta = pdObj.oldType === 'expense' ? -pdObj.oldAmount : pdObj.oldAmount;
      }
    }
    if (balanceDelta !== 0) {
      await tx.book.update({
        where: { id: txn.bookId },
        data: { balance: { increment: balanceDelta } }
      });
    }

    const mainVer = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true } });
    if (!mainVer) throw new Error('Transaction not found');
    
    const upd = await tx.transaction.updateMany({
      where: { id: txnId, version: mainVer.version },
      data: {
        amount: pdObj.oldAmount, type: pdObj.oldType, category: pdObj.oldCategory,
        note: pdObj.oldNote, recipientUserId: pdObj.oldRecipientUserId || null,
        reconStatus: 'approved', pendingAction: null, pendingData: null,
        version: { increment: 1 }
      }
    });
    if (upd.count === 0) throw new Error('Concurrency conflict on pendingAction cancel restore');

    const legs = await getCounterpartLegsForChangeDelete(txn, book, tx);
    for (const leg of legs) {
      if (!leg.pendingAction) continue;
      const legPd = parsePendingData(leg.pendingData || pd);
      let legDelta = 0;
      if (leg.pendingAction === 'delete') {
        const legIsSend = leg.category === 'Send';
        if (!legIsSend) {
          legDelta = leg.type === 'expense' ? -leg.amount : leg.amount;
        }
      }
      if (legDelta !== 0) {
        await tx.book.update({
          where: { id: leg.bookId },
          data: { balance: { increment: legDelta } }
        });
      }
      const legVer = await tx.transaction.findUnique({ where: { id: leg.id }, select: { version: true } });
      if (!legVer) continue;

      const legRestoreData = {
        reconStatus: 'approved',
        pendingAction: null,
        pendingData: null,
        version: { increment: 1 }
      };
      // For delete: counterpart leg data was never modified during pending phase.
      // For edit: type was never in fieldUpdates — never restore type on counterpart.
      if (leg.pendingAction !== 'delete') {
        legRestoreData.amount = legPd.oldAmount;
        legRestoreData.category = legPd.oldCategory;
        legRestoreData.note = legPd.oldNote;
      }
      const updL = await tx.transaction.updateMany({
        where: { id: leg.id, version: legVer.version },
        data: legRestoreData
      });
      if (updL.count === 0) throw new Error('Concurrency conflict on counterpart pendingAction cancel');
    }
  });

  if (pdObj && pdObj.requestedBy) {
    const actionLabel = txn.pendingAction === 'edit' ? 'সম্পাদনা' : 'মুছে ফেলা';
    await createNotification(pdObj.requestedBy, 'REQUEST_CANCELLED', 'অনুরোধ বাতিল', `আপনার ${actionLabel} করার অনুরোধটি সফলভাবে বাতিল করা হয়েছে।`, txnId, null);
  }

  broadcast({ type: "data_changed" });
  return res.json({ message: 'Request cancelled successfully. Original values restored.' });
};

module.exports = { handleCancel };
