const { prisma } = require('../../../config/database');
const {
  checkApprovalBypass,
  recordChangeDeleteApproval, isChangeDeleteFullyApproved,
  getCounterpartLegsForChangeDelete, finalizeCounterpartLegsOnEditApprove,
  generateChainId, resolveOrgSourceTxnForMirror, syncCreatorPersonalMirrorStatus,
  rejectCreatorPersonalMirror, rejectFundSendChain, approveFundSendOrg,
  approveFundSendRecipient, updateTxnWithVersion
} = require('../../../helpers/index');
const { enrichTxn } = require('../../../helpers/enrichTxn');
const { broadcast, broadcastToUser, broadcastToUsers } = require('../../../websocket');

const handleApprove = async (ctx) => {
  const { txn, txnId, txnBook, book, user, req, res, deps, userName, approveHistoryEntry } = ctx;
  const { hasAdminOrEditorAccess, checkPermission, createNotification, getOrgAdminUserIds, parsePendingData } = deps;

  // Send on org/personal sender book: org admin must not approve — only the recipient accepts.
  if (txn.category === 'Send' && (txn.reconStatus === 'pending' || txn.reconStatus === 'pending_org') && txn.type === 'expense') {
    const srcBook = await prisma.book.findUnique({
      where: { id: txn.bookId },
      include: { organization: { select: { isPersonal: true } } }
    });
    if (srcBook) {
      let recipientUserId = txn.recipientUserId;
      let recipientOrgId = txn.recipientOrgId;
      if (!recipientUserId && !recipientOrgId && txn.linkedTransactionId) {
        const linked = await prisma.transaction.findUnique({
          where: { id: txn.linkedTransactionId },
          select: { recipientUserId: true, recipientOrgId: true }
        });
        recipientUserId = linked?.recipientUserId;
        recipientOrgId = linked?.recipientOrgId;
      }
      let isAuthorizedRecipient = false;
      if (recipientUserId) {
        isAuthorizedRecipient = req.user.id === recipientUserId;
      } else if (recipientOrgId) {
        isAuthorizedRecipient = await checkPermission(recipientOrgId, req.user.id, 'edit_all');
      }
      if (!isAuthorizedRecipient) {
        return res.status(403).json({
          error: { bn: 'এই সেন্ড প্রাপকের গ্রহণের অপেক্ষায় আছে। প্রাপকের বই থেকে অনুমোদন করুন।', en: 'This send is waiting for the recipient to accept. Approve from the recipient\'s book.' },
        });
      }
    }
  }

  // 2. Check if this is a pending creation step and the caller is NOT the recipient.
  if (!txn.pendingAction && (txn.reconStatus === 'pending' || txn.reconStatus === 'pending_recipient')) {
    let recipientUserId = null;
    let recipientOrgId = null;
    if (txn.type === 'expense' && txn.category === 'Send') {
      recipientUserId = txn.recipientUserId;
      recipientOrgId = txn.recipientOrgId;
    } else if (txn.type === 'income' && txn.category === 'Send') {
      recipientUserId = txn.recipientUserId;
      recipientOrgId = txn.recipientOrgId;
    } else if (txn.linkedTransactionId) {
      const linked = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
      if (linked && linked.type === 'expense' && linked.category === 'Send') {
        recipientUserId = linked.recipientUserId;
        recipientOrgId = linked.recipientOrgId;
      } else if (linked && linked.type === 'income' && linked.category === 'Send') {
        recipientUserId = linked.recipientUserId;
        recipientOrgId = linked.recipientOrgId;
      }
    }

    let isAuthorizedRecipient = false;
    if (recipientUserId) {
      isAuthorizedRecipient = req.user.id === recipientUserId;
    } else if (recipientOrgId) {
      isAuthorizedRecipient = await checkPermission(recipientOrgId, req.user.id, 'edit_all');
    }

    if (!isAuthorizedRecipient) {
      return res.status(403).json({ error: { bn: 'শুধু ট্রান্সফারের প্রাপক এটি গ্রহণ/অনুমোদন করতে পারেন।', en: 'Only the recipient of the transfer can accept/approve it.' } });
    }
  }

  // Handle pendingAction transactions (edit/delete/org_fund requests)
  if (txn.pendingAction) {
    if (txn.pendingAction === 'edit') {
      const updatedPendingData = recordChangeDeleteApproval(txn.pendingData, req.user.id, txnId);
      if (!isChangeDeleteFullyApproved(updatedPendingData)) {
        await prisma.$transaction(async (tx) => {
          await tx.transaction.update({
            where: { id: txnId },
            data: {
              pendingData: updatedPendingData,
              updateHistory: [...(txn.updateHistory || []), approveHistoryEntry]
            }
          });
          const legs = await getCounterpartLegsForChangeDelete(txn, txnBook, tx);
          for (const leg of legs) {
            await tx.transaction.update({
              where: { id: leg.id },
              data: { pendingData: updatedPendingData }
            });
          }
        });
        broadcast({ type: 'data_changed' });
        const remaining = (updatedPendingData.requiredApprovers || []).filter((id) => !(updatedPendingData.approvals || []).includes(id));
        return res.json({ message: `Edit approval recorded. Waiting for ${remaining.length} more approval(s).` });
      }

      await prisma.$transaction(async (tx) => {
        const current = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true, updateHistory: true } });
        if (!current) throw new Error('Transaction not found');
        const upd1 = await tx.transaction.updateMany({
          where: { id: txnId, version: current.version },
          data: {
            reconStatus: 'approved',
            pendingAction: null,
            pendingData: null,
            version: { increment: 1 },
            updateHistory: [...(current.updateHistory || []), approveHistoryEntry]
          }
        });
        if (upd1.count === 0) throw new Error('Concurrency conflict on edit-approve');

        const updated = await tx.transaction.findUnique({ where: { id: txnId } });
        if (updated) {
          const pd = parsePendingData(txn.pendingData);
          const oldAmount = (pd.oldAmount != null ? Number(pd.oldAmount) : updated.amount);
          const delta = txn.type === 'expense'
            ? (oldAmount - updated.amount)
            : (updated.amount - oldAmount);
          if (delta !== 0) {
            await tx.book.update({
              where: { id: txn.bookId },
              data: { balance: { increment: delta } }
            });
          }
        }
        await finalizeCounterpartLegsOnEditApprove(tx, txn, txnBook, approveHistoryEntry);
      });
      const updated = await prisma.transaction.findUnique({ where: { id: txnId } });
      broadcast({ type: "data_changed" });
      const pd = parsePendingData(txn.pendingData);
      if (pd && pd.requestedBy) {
        await createNotification(pd.requestedBy, 'EDIT_APPROVED', 'সম্পাদনা অনুমোদিত', `আপনার অনুরোধ করা ${txn.amount} টাকার এন্ট্রি সম্পাদনা অনুমোদিত হয়েছে।`, txnId, null);
      }
      return res.json({ transaction: updated, message: 'Edit approved' });
    } else if (txn.pendingAction === 'org_fund') {
      const pd = parsePendingData(txn.pendingData);
      const updatedPd = {
        ...pd,
        approvals: [...(pd.approvals || []), req.user.id]
      };
      const required = pd.requiredApprovers || [];
      const isFullyApproved = required.length === 0 ||
        required.every(id => updatedPd.approvals.includes(id));

      if (!isFullyApproved) {
        const updates = [];
        updates.push(
          prisma.transaction.update({
            where: { id: txnId },
            data: { pendingData: updatedPd }
          })
        );
        if (txn.linkedTransactionId) {
          updates.push(
            prisma.transaction.update({
              where: { id: txn.linkedTransactionId },
              data: { pendingData: updatedPd }
            })
          );
        }
        await prisma.$transaction(updates);
        broadcast({ type: 'data_changed' });
        return res.json({ message: { bn: 'অনুমোদন গৃহীত হয়েছে। আরো অনুমোদন প্রয়োজন।', en: 'Approval recorded. More approvals needed.' } });
      }

      await prisma.$transaction(async (tx) => {
        await tx.transaction.update({
          where: { id: txnId },
          data: {
            reconStatus: 'approved',
            pendingAction: null,
            pendingData: null,
            updateHistory: [...(txn.updateHistory || []), approveHistoryEntry]
          }
        });
        if (txn.linkedTransactionId) {
          await tx.transaction.update({
            where: { id: txn.linkedTransactionId },
            data: {
              reconStatus: 'approved',
              pendingAction: null,
              pendingData: null,
              updateHistory: [...(txn.updateHistory || []), approveHistoryEntry]
            }
          });
        }
      });

      broadcast({ type: 'data_changed' });
      await createNotification(pd.requestedBy, 'ORG_FUND_APPROVED',
        'তহবিল ব্যবহার অনুমোদিত / Fund usage approved',
        `আপনার ${pd.amount || txn.amount} টাকার তহবিল ব্যবহার অনুমোদিত হয়েছে। / Your ${pd.amount || txn.amount} Tk fund usage has been approved.`,
        txnId, null);
      const updated = await prisma.transaction.findUnique({ where: { id: txnId } });
      return res.json({ transaction: updated, message: { bn: 'তহবিল ব্যবহার অনুমোদিত', en: 'Fund usage approved' } });
    } else if (txn.pendingAction === 'delete') {
      const updatedPendingData = recordChangeDeleteApproval(txn.pendingData, req.user.id, txnId);
      if (!isChangeDeleteFullyApproved(updatedPendingData)) {
        await prisma.$transaction(async (tx) => {
          await tx.transaction.update({
            where: { id: txnId },
            data: {
              pendingData: updatedPendingData,
              updateHistory: [...(txn.updateHistory || []), approveHistoryEntry]
            }
          });
          const legs = await getCounterpartLegsForChangeDelete(txn, txnBook, tx);
          for (const leg of legs) {
            await tx.transaction.update({
              where: { id: leg.id },
              data: { pendingData: updatedPendingData }
            });
          }
        });
        broadcast({ type: 'data_changed' });
        const remaining = (updatedPendingData.requiredApprovers || []).filter((id) => !(updatedPendingData.approvals || []).includes(id));
        return res.json({ message: `Delete approval recorded. Waiting for ${remaining.length} more approval(s).` });
      }

      await prisma.$transaction(async (tx) => {
        const isSend = txn.category === 'Send';
        if (isSend) {
          const balanceAdjustment = txn.type === 'expense' ? txn.amount : -txn.amount;
          await tx.book.update({ where: { id: txn.bookId }, data: { balance: { increment: balanceAdjustment } } });
        }

        const legs = await getCounterpartLegsForChangeDelete(txn, txnBook, tx);
        for (const leg of legs) {
          if (isSend) {
            const legAdj = leg.type === 'expense' ? leg.amount : -leg.amount;
            await tx.book.update({ where: { id: leg.bookId }, data: { balance: { increment: legAdj } } });
          }
          await tx.transaction.delete({ where: { id: leg.id } });
        }
        await tx.transaction.delete({ where: { id: txnId } });
      });
      broadcast({ type: "data_changed" });
      return res.json({ message: 'Deletion approved, transaction removed' });
    }
  }

  // Counter-approve inside approve action (legacy path)
  if (txn.counterProposedAmount != null && txn.counterProposedBy !== req.user.id) {
    const finalAmount = txn.counterProposedAmount;
    const amountDiff = finalAmount - txn.amount;

    await prisma.$transaction(async (tx) => {
      if (txn.linkedTransactionId) {
        const linked = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { bookId: true } });
        if (linked) {
          await tx.transaction.update({
            where: { id: txn.linkedTransactionId },
            data: { amount: finalAmount, category: 'Send', reconStatus: 'approved', counterProposedAmount: null, counterProposedBy: null }
          });
          await tx.book.update({
            where: { id: linked.bookId },
            data: { balance: { increment: amountDiff } }
          });
        }
      }

      await tx.transaction.update({
        where: { id: txnId },
        data: { amount: finalAmount, reconStatus: 'approved', counterProposedAmount: null, counterProposedBy: null }
      });

      if (amountDiff !== 0) {
        const bookAdj = txn.type === 'expense' ? amountDiff : -amountDiff;
        await tx.book.update({
          where: { id: txn.bookId },
          data: { balance: { increment: bookAdj } }
        });
      }
    });

    const updated = await prisma.transaction.findUnique({ where: { id: txnId } });
    broadcast({ type: "data_changed" });
    return res.json({ transaction: updated, message: 'Counter-approved, amount updated and approved' });
  }

  // --- PENDING_ORG → advance to next stage ---
  if (txn.reconStatus === 'pending_org') {
    if (txn.chainType === 'fund_send' && txn.type === 'income') {
      return res.status(400).json({ error: { bn: 'ফান্ড অর্গানাইজেশনকে প্রথমে সেন্ড অনুমোদন করতে হবে।', en: 'Fund organization must approve the send first' } });
    }

    const isSend = txn.category === 'Send' && txn.linkedTransactionId;
    if (isSend || (txn.category === 'Send' && (txn.recipientUserId || txn.recipientOrgId))) {
      const nextStatus = 'pending';

      let fundSendOrgResult = null;
      await prisma.$transaction(async (tx) => {
        if (txn.chainType === 'fund_send' && txn.chainId) {
          fundSendOrgResult = await approveFundSendOrg(tx, txn, approveHistoryEntry);
          return;
        }

        const main = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true, updateHistory: true } });
        if (!main) throw new Error('Transaction not found');
        const upd1 = await tx.transaction.updateMany({
          where: { id: txnId, version: main.version },
          data: {
            reconStatus: nextStatus,
            version: { increment: 1 },
            updateHistory: [...(main.updateHistory || []), approveHistoryEntry]
          }
        });
        if (upd1.count === 0) throw new Error('Concurrency conflict on pending_org advance');

        if (txn.linkedTransactionId) {
          const linked = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { version: true, updateHistory: true } });
          if (linked) {
            const upd2 = await tx.transaction.updateMany({
              where: { id: txn.linkedTransactionId, version: linked.version },
              data: {
                reconStatus: nextStatus,
                version: { increment: 1 },
                updateHistory: [...(linked.updateHistory || []), approveHistoryEntry]
              }
            });
            if (upd2.count === 0) throw new Error('Concurrency conflict on linked pending_org advance');
          }
        }

        const orgSource = await resolveOrgSourceTxnForMirror(txn, tx);
        if (orgSource && orgSource.chainType !== 'fund_send') {
          await syncCreatorPersonalMirrorStatus(tx, orgSource, nextStatus, approveHistoryEntry);
        }
      });

      if (fundSendOrgResult?.final) {
        broadcast({ type: 'data_changed' });
        return res.json({ message: 'Org approved, transaction completed' });
      }
      if (fundSendOrgResult && !fundSendOrgResult.final) {
        broadcast({ type: 'data_changed' });
        return res.json({ message: 'Org approved, waiting for recipient acceptance' });
      }

      if (txn.recipientUserId) {
        broadcastToUser(txn.recipientUserId, { type: 'pending_send_received', transaction: txn });
      } else if (txn.recipientOrgId) {
        const recipientAdmins = await prisma.organizationMember.findMany({
          where: { organizationId: txn.recipientOrgId, status: 'active', OR: [{ role: 'admin' }, { permissions: { has: 'edit_all' } }] },
          select: { userId: true }
        });
        const adminIds = recipientAdmins.map(a => a.userId);
        const enriched = await enrichTxn(txn);
        broadcastToUsers(adminIds, { type: "pending_send_received", transaction: enriched });
      }
      broadcast({ type: "data_changed" });
      return res.json({ message: 'Org approved, waiting for recipient acceptance' });
    } else {
      if (txn.orgFundId) {
        const targetBook = await prisma.book.findUnique({ where: { id: txn.orgFundId } });
        if (targetBook) {
          await prisma.$transaction(async (tx) => {
            const upd = await tx.transaction.updateMany({
              where: { id: txnId, version: txn.version },
              data: {
                reconStatus: 'approved',
                version: { increment: 1 },
                updateHistory: [...(txn.updateHistory || []), approveHistoryEntry]
              }
            });
            if (upd.count === 0) throw new Error('Concurrency conflict on voucher approve');
            const orgSource = await resolveOrgSourceTxnForMirror(txn, tx);
            if (orgSource) {
              await syncCreatorPersonalMirrorStatus(tx, orgSource, 'approved', approveHistoryEntry);
            }
          });
          broadcast({ type: "data_changed" });
          const updated = await prisma.transaction.findUnique({ where: { id: txnId } });
          return res.json({ transaction: updated, message: 'Voucher approved' });
        }
      }

      const updated = await prisma.$transaction(async (tx) => {
        const approvedTxn = await updateTxnWithVersion(txnId, txn.version, {
          reconStatus: 'approved',
          updateHistory: [...(txn.updateHistory || []), approveHistoryEntry]
        }, tx);
        const orgSource = await resolveOrgSourceTxnForMirror(txn, tx);
        if (orgSource) {
          await syncCreatorPersonalMirrorStatus(tx, orgSource, 'approved', approveHistoryEntry);
        }
        return approvedTxn;
      });
      broadcast({ type: 'data_changed' });
      await createNotification(txn.createdById, 'TRANSACTION_APPROVED', 'এন্ট্রি অনুমোদিত', `আপনার ${txn.amount} টাকার এন্ট্রি অনুমোদিত হয়েছে।`, txnId, null);
      return res.json({ transaction: updated, message: 'Transaction approved' });
    }
  }

  // --- PENDING / PENDING_RECIPIENT → approve (green) ---
  if (txn.reconStatus === 'pending' || txn.reconStatus === 'pending_recipient') {
    let fundSendRecipientResult = null;
    await prisma.$transaction(async (tx) => {
      if (txn.chainType === 'fund_send' && txn.chainId) {
        fundSendRecipientResult = await approveFundSendRecipient(tx, txn, approveHistoryEntry);
      } else {
        const main = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true, updateHistory: true } });
        if (!main) throw new Error('Transaction not found');
        const upd1 = await tx.transaction.updateMany({
          where: { id: txnId, version: main.version },
          data: {
            reconStatus: 'approved',
            counterProposedAmount: null,
            counterProposedBy: null,
            version: { increment: 1 },
            updateHistory: [...(main.updateHistory || []), approveHistoryEntry]
          }
        });
        if (upd1.count === 0) throw new Error('Concurrency conflict on pending_recipient approve');

        if (txn.linkedTransactionId) {
          const linked = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { version: true, updateHistory: true } });
          if (linked) {
            const upd2 = await tx.transaction.updateMany({
              where: { id: txn.linkedTransactionId, version: linked.version },
              data: {
                reconStatus: 'approved',
                counterProposedAmount: null,
                counterProposedBy: null,
                version: { increment: 1 },
                updateHistory: [...(linked.updateHistory || []), approveHistoryEntry]
              }
            });
            if (upd2.count === 0) throw new Error('Concurrency conflict on linked pending_recipient approve');
          }
        }



        if (txn.type === 'income') {
          const isPersonalOwner = await tx.organizationMember.findFirst({
            where: { userId: req.user.id, organization: { isPersonal: true, books: { some: { id: txn.bookId } } } }
          });
          if (isPersonalOwner) {
            const deficits = await tx.transaction.findMany({
              where: {
                chainType: 'deficit',
                createdById: req.user.id,
                bookId: txn.bookId,
                adjustedAmount: null,
                isLiability: false,
                reconStatus: 'approved'
              }
            });
            const totalDeficit = deficits.reduce((sum, d) => sum + d.amount, 0);
            if (totalDeficit > 0) {
              const adjustmentAmount = Math.min(totalDeficit, txn.amount);
              const adjChainId = generateChainId();
              await tx.transaction.create({
                data: {
                  bookId: txn.bookId,
                  amount: adjustmentAmount,
                  type: 'expense',
                  note: `Auto-adjustment: ${adjustmentAmount} Tk deficit deducted from new fund release`,
                  category: 'Adjustment',
                  createdById: req.user.id,
                  reconStatus: 'approved',
                  chainId: adjChainId,
                  chainType: 'adjustment'
                }
              });
              await tx.book.update({
                where: { id: txn.bookId },
                data: { balance: { decrement: adjustmentAmount } }
              });
              for (const d of deficits) {
                await tx.transaction.update({
                  where: { id: d.id },
                  data: { adjustedAmount: d.amount }
                });
              }
            }
          }
        }

        const orgSource = await resolveOrgSourceTxnForMirror(txn, tx);
        if (orgSource && orgSource.chainType !== 'fund_send') {
          const mirrorStatus =
            fundSendRecipientResult && !fundSendRecipientResult.final ? 'pending' : 'approved';
          await syncCreatorPersonalMirrorStatus(tx, orgSource, mirrorStatus, approveHistoryEntry, {
            counterProposedAmount: null,
            counterProposedBy: null
          });
        }
      }
    });

    if (fundSendRecipientResult && !fundSendRecipientResult.final) {
      broadcast({ type: 'data_changed' });
      return res.json({ message: 'Accepted, waiting for organization approval' });
    }

    if (txn.type === 'income' && (fundSendRecipientResult?.final !== false)) {
      const deficits = await prisma.transaction.findMany({
        where: {
          chainType: 'deficit',
          createdById: req.user.id,
          bookId: txn.bookId,
          adjustedAmount: { not: null },
          reconStatus: 'approved'
        }
      });
      const totalAdj = deficits.reduce((s, d) => s + (d.adjustedAmount || 0), 0);
      if (totalAdj > 0) {
        const txnBook = await prisma.book.findUnique({ where: { id: txn.bookId }, select: { organizationId: true } });
        broadcastToUsers(
          (await getOrgAdminUserIds(txnBook?.organizationId || '')) || [],
          { type: "deficit_adjusted", message: { bn: `${totalAdj} টাকা ঘাটতি নতুন তহবিল থেকে কেটে নেওয়া হয়েছে`, en: `${totalAdj} Tk deficit deducted from new fund release` } }
        );
      }
    }

    broadcast({ type: "data_changed" });
    await createNotification(txn.createdById, 'TRANSACTION_FULLY_APPROVED', 'এন্ট্রি সম্পূর্ণ অনুমোদিত', `আপনার ${txn.amount} টাকার এন্ট্রি সম্পূর্ণ অনুমোদিত হয়েছে।`, txnId, null);
    return res.json({ message: 'Transaction fully approved' });
  }

  return res.status(400).json({ error: { bn: 'লেনদেন অনুমোদনের জন্য উপযুক্ত নয়।', en: 'Transaction not eligible for approval' } });
};

module.exports = { handleApprove };
