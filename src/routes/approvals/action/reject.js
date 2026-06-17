const { prisma } = require('../../../config/database');
const {
  getCounterpartLegsForChangeDelete,
  rejectCreatorPersonalMirror,
  resolveOrgSourceTxnForMirror,
  rejectFundSendChain,
} = require('../../../helpers/index');
const { broadcast, broadcastToUser, broadcastToUsers } = require('../../../websocket');

const handleReject = async (ctx) => {
  const { txn, txnId, txnBook, book, req, res, deps, userName, rejectHistoryEntry } = ctx;
  const { hasAdminOrEditorAccess, checkPermission, createNotification, getOrgAdminUserIds, parsePendingData } = deps;

  if (txn.pendingAction) {
    if (txn.pendingAction === 'org_fund') {
      const pd = parsePendingData(txn.pendingData);
      const orgBookId = pd?.orgBookId || txn.orgFundId;
      const amount = pd?.amount || txn.amount;

      // Determine which leg is personal vs org counterpart
      const isPersonalLeg = book?.organization?.isPersonal;
      const personalTxnId = isPersonalLeg ? txnId : txn.linkedTransactionId;
      const orgCounterpartId = isPersonalLeg ? txn.linkedTransactionId : txnId;

      await prisma.$transaction(async (tx) => {
        // Reverse org book balance
        if (orgBookId) {
          await tx.book.update({
            where: { id: orgBookId },
            data: { balance: { increment: amount } }
          });
        }

        // Delete org counterpart (regardless of which leg was rejected)
        if (orgCounterpartId) {
          const counterpart = await tx.transaction.findUnique({
            where: { id: orgCounterpartId }
          });
          if (counterpart) {
            await tx.transaction.delete({
              where: { id: orgCounterpartId }
            });
          }
        }

        // Set personal txn to rejected — keep orgFundId intact, no balance reversal
        if (personalTxnId) {
          const mainVer = await tx.transaction.findUnique({
            where: { id: personalTxnId },
            select: { version: true, updateHistory: true }
          });
          if (!mainVer) throw new Error('Personal transaction not found');
          const upd = await tx.transaction.updateMany({
            where: { id: personalTxnId, version: mainVer.version },
            data: {
              reconStatus: 'rejected',
              pendingAction: null,
              pendingData: null,
              linkedTransactionId: null,
              version: { increment: 1 },
              updateHistory: [...(mainVer.updateHistory || []), rejectHistoryEntry]
            }
          });
          if (upd.count === 0) throw new Error('Concurrency conflict on org_fund reject');
        }
      });

      if (pd?.requestedBy) {
        await createNotification(pd.requestedBy, 'ORG_FUND_REJECTED',
          'তহবিল ব্যবহার প্রত্যাখ্যান / Fund usage rejected',
          `আপনার তহবিল ব্যবহারের অনুরোধ প্রত্যাখ্যান করা হয়েছে। / Your fund usage request has been rejected.`,
          personalTxnId || txnId, null);
      }
      broadcast({ type: 'data_changed' });
      return res.json({ message: { bn: 'তহবিল ব্যবহার প্রত্যাখ্যান করা হয়েছে, অর্গ ব্যালেন্স ফেরত নেয়া হয়েছে', en: 'Fund usage rejected, org balance reversed' } });
    }

    const pd = txn.pendingData;
    if (pd && book) {
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
        if (upd.count === 0) throw new Error('Concurrency conflict on pendingAction reject restore');

        const legs = await getCounterpartLegsForChangeDelete(txn, book, tx);
        for (const leg of legs) {
          if (!leg.pendingAction) continue;
          const legPd = parsePendingData(leg.pendingData || pd);
          let legDelta = 0;
          if (leg.pendingAction === 'delete') {
            const legIsSend = leg.category === 'Send';
            if (!legIsSend) {
              // Use leg's own type (not source's oldType from pendingData) for correct balance restoration
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
          // For delete: counterpart leg data was never modified during pending phase,
          // only pendingAction/pendingData were set. Don't overwrite any fields.
          // For edit: type was never in fieldUpdates — legPd.oldType is SOURCE's type,
          // not counterpart's. Never restore type on counterpart legs.
          if (leg.pendingAction !== 'delete') {
            legRestoreData.amount = legPd.oldAmount;
            legRestoreData.category = legPd.oldCategory;
            legRestoreData.note = legPd.oldNote;
          }
          const updL = await tx.transaction.updateMany({
            where: { id: leg.id, version: legVer.version },
            data: legRestoreData
          });
          if (updL.count === 0) throw new Error('Concurrency conflict on counterpart pendingAction reject');
        }
      });

      if (pdObj && pdObj.requestedBy) {
        const actionLabel = txn.pendingAction === 'edit' ? 'সম্পাদনা' : 'মুছে ফেলা';
        await createNotification(pdObj.requestedBy, txn.pendingAction === 'edit' ? 'EDIT_REJECTED' : 'DELETE_REJECTED', `${actionLabel} প্রত্যাখ্যান`, `আপনার অনুরোধ করা ${actionLabel} প্রত্যাখ্যান করা হয়েছে।`, txnId, null);
      }
    }
    broadcast({ type: "data_changed" });
    return res.json({ message: 'Changes rejected, original values restored' });
  }

  if (!['pending_org', 'pending_recipient', 'pending'].includes(txn.reconStatus)) {
    return res.status(400).json({ error: 'Transaction is not in a rejectable state' });
  }

  const isSend = txn.category === 'Send';
  const isPending = txn.reconStatus === 'pending';
  let isReceiver = false;
  if (isSend && isPending) {
    if (txn.recipientUserId) {
      isReceiver = txn.recipientUserId === req.user.id;
    } else if (txn.recipientOrgId) {
      isReceiver = await checkPermission(txn.recipientOrgId, req.user.id, 'edit_all');
    }
    if (!isReceiver && txn.linkedTransactionId) {
      const linked = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { recipientUserId: true, recipientOrgId: true } });
      if (linked) {
        if (linked.recipientUserId) isReceiver = linked.recipientUserId === req.user.id;
        else if (linked.recipientOrgId) isReceiver = await checkPermission(linked.recipientOrgId, req.user.id, 'edit_all');
      }
    }
  }

  if (!isReceiver && !(await hasAdminOrEditorAccess(book.organizationId, req.user.id))) {
    return res.status(403).json({ error: 'Access denied' });
  }

  let isLiabilityReject = false;
  if (txn.chainType === 'deficit' && txn.linkedTransactionId) {
    const linked = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
    if (linked && linked.reconStatus === 'approved') {
      isLiabilityReject = true;
    }
  }

  if (txn.reconStatus === 'pending_org' && txn.orgFundId) {
    await prisma.$transaction(async (tx) => {
      const upd = await tx.transaction.updateMany({
        where: { id: txnId, version: txn.version },
        data: {
          reconStatus: 'rejected',
          version: { increment: 1 },
          updateHistory: [...(txn.updateHistory || []), rejectHistoryEntry]
        }
      });
      if (upd.count === 0) throw new Error('Concurrency conflict on voucher reject');
      await rejectCreatorPersonalMirror(tx, txn, rejectHistoryEntry);
    });
    broadcast({ type: 'data_changed' });
    return res.json({ message: 'Voucher rejected' });
  }

  if (txn.chainType === 'fund_send' && txn.chainId) {
    await prisma.$transaction(async (tx) => {
      await rejectFundSendChain(tx, txn, rejectHistoryEntry);
    });
    broadcast({ type: 'data_changed' });
    return res.json({ message: 'Fund send rejected' });
  }

  await prisma.$transaction(async (tx) => {
    const mainCurrent = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true, updateHistory: true, type: true, bookId: true, amount: true, linkedTransactionId: true } });
    if (!mainCurrent) throw new Error('Transaction not found');
    
    if (isSend) {
      // Find which is income and which is expense
      let incomeLeg = null;
      let expenseLeg = null;
      let linkedCurrent = null;
      
      if (mainCurrent.linkedTransactionId) {
        linkedCurrent = await tx.transaction.findUnique({ where: { id: mainCurrent.linkedTransactionId }, select: { id: true, type: true, bookId: true, amount: true, version: true, updateHistory: true } });
      }

      if (mainCurrent.type === 'income') {
        incomeLeg = { ...mainCurrent, id: txnId };
        expenseLeg = linkedCurrent;
      } else {
        expenseLeg = { ...mainCurrent, id: txnId };
        incomeLeg = linkedCurrent;
      }

      // Delete income leg and reverse its balance
      if (incomeLeg) {
        await tx.book.update({
          where: { id: incomeLeg.bookId },
          data: { balance: { decrement: incomeLeg.amount } }
        });
        await tx.transaction.delete({ where: { id: incomeLeg.id } });
      }

      // Update expense leg to rejected, no refund, clear linkedTransactionId
      if (expenseLeg) {
        const updExp = await tx.transaction.updateMany({
          where: { id: expenseLeg.id, version: expenseLeg.version },
          data: {
            reconStatus: 'rejected',
            pendingAction: null,
            pendingData: null,
            counterProposedAmount: null,
            counterProposedBy: null,
            linkedTransactionId: null,
            version: { increment: 1 },
            updateHistory: [...(expenseLeg.updateHistory || []), rejectHistoryEntry]
          }
        });
        if (updExp.count === 0) throw new Error('Concurrency conflict on expense leg reject');
      }
    } else {
      // Non-Send legacy reject logic
      const updMain = await tx.transaction.updateMany({
        where: { id: txnId, version: mainCurrent.version },
        data: {
          reconStatus: 'rejected',
          pendingAction: null,
          pendingData: null,
          counterProposedAmount: null,
          counterProposedBy: null,
          isLiability: isLiabilityReject || undefined,
          version: { increment: 1 },
          updateHistory: [...(mainCurrent.updateHistory || []), rejectHistoryEntry]
        }
      });
      if (updMain.count === 0) throw new Error('Concurrency conflict on reject');

      const shouldReverseMain = mainCurrent.type === 'expense' || txn.reconStatus === 'approved';
      if (shouldReverseMain) {
        const balanceAdjustment = mainCurrent.type === 'expense' ? mainCurrent.amount : -mainCurrent.amount;
        await tx.book.update({
          where: { id: mainCurrent.bookId },
          data: { balance: { increment: balanceAdjustment } }
        });
      }

      if (mainCurrent.linkedTransactionId) {
        const linked = await tx.transaction.findUnique({ where: { id: mainCurrent.linkedTransactionId } });
        if (linked) {
          const linkedVersion = linked.version;
          if (isLiabilityReject) {
            const updLink = await tx.transaction.updateMany({
              where: { id: mainCurrent.linkedTransactionId, version: linkedVersion },
              data: {
                reconStatus: 'rejected',
                isLiability: true,
                pendingAction: null,
                pendingData: null,
                counterProposedAmount: null,
                counterProposedBy: null,
                version: { increment: 1 },
                updateHistory: [...(linked.updateHistory || []), rejectHistoryEntry]
              }
            });
            if (updLink.count === 0) throw new Error('Concurrency conflict on linked liability reject');
          } else if (['pending_org', 'pending_recipient', 'pending'].includes(linked.reconStatus)) {
            const updLink = await tx.transaction.updateMany({
              where: { id: mainCurrent.linkedTransactionId, version: linkedVersion },
              data: {
                reconStatus: 'rejected',
                pendingAction: null,
                pendingData: null,
                counterProposedAmount: null,
                counterProposedBy: null,
                version: { increment: 1 },
                updateHistory: [...(linked.updateHistory || []), rejectHistoryEntry]
              }
            });
            if (updLink.count === 0) throw new Error('Concurrency conflict on linked reject');
            const shouldReverseLinked = linked.type === 'expense' || linked.reconStatus === 'approved';
            if (shouldReverseLinked) {
              const linkedBalanceAdj = linked.type === 'income' ? -linked.amount : linked.amount;
              await tx.book.update({
                where: { id: linked.bookId },
                data: { balance: { increment: linkedBalanceAdj } }
              });
            }
          }
        }
      }
    }

    const orgSource = await resolveOrgSourceTxnForMirror(txn, tx);
    if (orgSource && orgSource.chainType !== 'fund_send') {
      await rejectCreatorPersonalMirror(tx, orgSource, rejectHistoryEntry);
    }
  });

  if (isLiabilityReject) {
    const txnBookForNotify = await prisma.book.findUnique({ where: { id: txn.bookId }, select: { organizationId: true } });
    broadcastToUsers(
      (await getOrgAdminUserIds(txnBookForNotify?.organizationId || '')) || [],
      { type: "deficit_liability", message: { bn: `${txn.amount} টাকা ঘাটতি ব্যক্তিগত দায় হিসেবে লক করা হয়েছে`, en: `${txn.amount} Tk deficit locked as personal liability` } }
    );
  }

  const updated = await prisma.transaction.findUnique({ where: { id: txnId } });
  broadcast({ type: "data_changed" });
  await createNotification(txn.createdById, 'TRANSACTION_REJECTED', 'এন্ট্রি প্রত্যাখ্যান', `আপনার ${txn.amount} টাকার এন্ট্রি প্রত্যাখ্যান করা হয়েছে।`, txnId, null);
  return res.json({ transaction: updated, message: 'Transaction rejected and reversed' });
};

module.exports = { handleReject };
