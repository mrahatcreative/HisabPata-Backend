const { prisma } = require('../../config/database');
const {
  checkApprovalBypass,
  recordChangeDeleteApproval, isChangeDeleteFullyApproved,
  getCounterpartLegsForChangeDelete, finalizeCounterpartLegsOnEditApprove,
  generateChainId, resolveOrgSourceTxnForMirror, syncCreatorPersonalMirrorStatus,
  rejectCreatorPersonalMirror, rejectFundSendChain, approveFundSendOrg,
  approveFundSendRecipient, updateTxnWithVersion
} = require('../../helpers/index');
const { enrichTxn } = require('../../helpers/enrichTxn');
const { broadcast, broadcastToUser, broadcastToUsers } = require('../../websocket');

module.exports = function(app, { authenticateToken, hasAdminOrEditorAccess, checkPermission, createNotification, getOrgAdminUserIds, resolveApprovalOrgId, parsePendingData }) {

// --- ORG FUND APPROVAL / REJECTION ---
app.post('/api/transactions/:id/action', authenticateToken, async (req, res) => {
  try {
    const { action } = req.body; // "approve" | "reject" | "counter_approve" | "reject_modification"
    const txnId = req.params.id;

    if (!['approve', 'reject', 'counter_approve', 'reject_modification'].includes(action)) {
      return res.status(400).json({ error: 'Action must be "approve", "reject", "counter_approve", or "reject_modification"' });
    }

    const txn = await prisma.transaction.findUnique({ where: { id: txnId } });
    if (!txn) return res.status(404).json({ error: 'Transaction not found' });

    // Prevent double approval of already approved transaction
    if (action === 'approve' && txn.reconStatus === 'approved' && !txn.pendingAction && txn.counterProposedAmount == null) {
      return res.json({ transaction: txn, message: 'Transaction is already approved' });
    }

    const txnBook = await prisma.book.findUnique({ where: { id: txn.bookId } });
    if (!txnBook) return res.status(404).json({ error: 'Book not found' });

    // Fetch details of user taking action to save in updateHistory
    const user = await prisma.user.findUnique({ where: { id: req.user.id }, select: { name: true } });
    const userName = user?.name || 'Unknown';
    const approveHistoryEntry = {
      timestamp: new Date().toISOString(),
      userId: req.user.id,
      userName,
      action: 'approve'
    };
    const rejectHistoryEntry = {
      timestamp: new Date().toISOString(),
      userId: req.user.id,
      userName,
      action: 'reject'
    };

    // Verify caller is admin/editor of the transaction's org
    // OR that the caller is the recipient of this or the linked transaction (user or org admin/editor)
    let isRecipient = false;
    if (txn.recipientUserId) {
      isRecipient = txn.recipientUserId === req.user.id;
    } else if (txn.recipientOrgId) {
      isRecipient = await checkPermission(txn.recipientOrgId, req.user.id, 'edit_all');
    }
    if (!isRecipient && txn.linkedTransactionId) {
      const linked = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { recipientUserId: true, recipientOrgId: true } });
      if (linked) {
        if (linked.recipientUserId) {
          isRecipient = linked.recipientUserId === req.user.id;
        } else if (linked.recipientOrgId) {
          isRecipient = await checkPermission(linked.recipientOrgId, req.user.id, 'edit_all');
        }
      }
    }

    // Also check if the caller is admin/editor of the fund's org (for vouchers from personal books)
    let hasFundOrgAccess = false;
    if (txn.orgFundId) {
      const fundBook = await prisma.book.findUnique({ where: { id: txn.orgFundId }, select: { organizationId: true } });
      if (fundBook) {
        hasFundOrgAccess = await hasAdminOrEditorAccess(fundBook.organizationId, req.user.id);
      } else {
        const fundTxn = await prisma.transaction.findUnique({ where: { id: txn.orgFundId }, select: { bookId: true } });
        if (fundTxn) {
          const fundTxnBook = await prisma.book.findUnique({ where: { id: fundTxn.bookId }, select: { organizationId: true } });
          if (fundTxnBook) {
            hasFundOrgAccess = await hasAdminOrEditorAccess(fundTxnBook.organizationId, req.user.id);
          }
        }
      }
    }

    const isSender = txn.createdById === req.user.id;
    if (!isRecipient && !(await hasAdminOrEditorAccess(txnBook.organizationId, req.user.id)) && !hasFundOrgAccess && !(action === 'counter_approve' && isSender)) {
      return res.status(403).json({ error: 'Only admins, editors, or the recipient can approve/reject transactions' });
    }

    // Edit/delete requests: requester cannot self-approve; only listed parties can approve
    if (txn.pendingAction && ['edit', 'delete'].includes(txn.pendingAction)) {
      const pendingDataObj = parsePendingData(txn.pendingData);
      if (pendingDataObj.requestedBy === req.user.id) {
        const dualLeg = pendingDataObj.dualLegSameUser === true;
        if (!dualLeg || txn.id === pendingDataObj.requestedFromTxnId) {
          return res.status(403).json({
            error: 'Approve or reject from the linked book entry (the other leg), not the row you requested from.'
          });
        }
      }
      const required = pendingDataObj.requiredApprovers || [];
      const orgAnyOf = pendingDataObj.orgApprovalAnyOf || [];
      if (required.length > 0 || orgAnyOf.length > 0) {
        const canApprove = required.includes(req.user.id) || orgAnyOf.includes(req.user.id);
        if (!canApprove) {
          return res.status(403).json({ error: 'You are not authorized to approve this edit/delete request.' });
        }
      }
    }

    // Send on org/personal sender book: org admin must not approve — only the recipient accepts.
    if (action === 'approve' && txn.category === 'Send' && (txn.reconStatus === 'pending' || txn.reconStatus === 'pending_org') && txn.type === 'expense') {
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
            error: 'This send is waiting for the recipient to accept. Approve from the recipient\'s book.',
          });
        }
      }
    }

    // 2. Check if this is a pending creation step and the caller is NOT the recipient.
    if (action === 'approve' && (txn.reconStatus === 'pending' || txn.reconStatus === 'pending_recipient')) {
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
        return res.status(403).json({ error: 'Only the recipient of the transfer can accept/approve it.' });
      }
    }

    // --- REJECT MODIFICATION (sender rejects recipient's proposed change) ---
    if (action === 'reject_modification') {
      const updates = [];
      updates.push(
        prisma.transaction.update({
          where: { id: txnId },
          data: { counterProposedAmount: null, counterProposedBy: null }
        })
      );
      if (txn.linkedTransactionId) {
        updates.push(
          prisma.transaction.update({
            where: { id: txn.linkedTransactionId },
            data: { counterProposedAmount: null, counterProposedBy: null }
          })
        );
      }
      await prisma.$transaction(updates);
      broadcast({ type: "data_changed" });
      return res.json({ message: 'Modification rejected, original amount preserved' });
    }

    // --- COUNTER-APPROVE (sender accepts recipient's proposed change) ---
    if (action === 'counter_approve') {
      if (txn.counterProposedAmount == null) {
        return res.status(400).json({ error: 'No modification to counter-approve' });
      }
      if (txn.counterProposedBy === req.user.id) {
        return res.status(403).json({ error: 'You cannot approve your own counter-proposal' });
      }
      const finalAmount = txn.counterProposedAmount;
      const linkedId = txn.linkedTransactionId;
      if (!linkedId) {
        return res.status(400).json({ error: 'No linked transaction found' });
      }
      const linkedTxn = await prisma.transaction.findUnique({ where: { id: linkedId } });
      if (!linkedTxn) return res.status(404).json({ error: 'Linked transaction not found' });

      // Identify source (expense in org book) vs recipient (income in personal book)
      const sourceTxn = txn.type === 'expense' ? txn : linkedTxn;
      const recipientTxn = txn.type === 'income' ? txn : linkedTxn;

      // Adjust balances from old amount to new amount
      // Source (expense): balance was decremented by old amount, now should be decremented by new amount
      const sourceDiff = sourceTxn.amount - finalAmount;
      // Recipient (income): balance was incremented by old amount, now should be incremented by new amount
      const recipientDiff = finalAmount - recipientTxn.amount;

      await prisma.$transaction([
        prisma.transaction.update({
          where: { id: sourceTxn.id },
          data: {
            amount: finalAmount,
            reconStatus: 'approved',
            counterProposedAmount: null,
            counterProposedBy: null,
            updateHistory: [...(sourceTxn.updateHistory || []), approveHistoryEntry]
          }
        }),
        prisma.transaction.update({
          where: { id: recipientTxn.id },
          data: {
            amount: finalAmount,
            reconStatus: 'approved',
            counterProposedAmount: null,
            counterProposedBy: null,
            updateHistory: [...(recipientTxn.updateHistory || []), approveHistoryEntry]
          }
        }),
        prisma.book.update({
          where: { id: sourceTxn.bookId },
          data: { balance: { increment: sourceDiff } }
        }),
        prisma.book.update({
          where: { id: recipientTxn.bookId },
          data: { balance: { increment: recipientDiff } }
        })
      ]);
      broadcast({ type: "data_changed" });
      return res.json({ message: 'Counter-approved, amount updated and approved' });
    }

    if (action === 'approve') {
      // Handle pendingAction transactions (edit/delete requests)
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
              // Balance stays effective during pendingAction. Only apply the DIFFERENCE
              // between old and new amounts, not the full balance.
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
            // Balance already reversed when pending delete was created — just delete entries
            const legs = await getCounterpartLegsForChangeDelete(txn, txnBook, tx);
            for (const leg of legs) {
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
          // Update amount on linked transaction if exists
          if (txn.linkedTransactionId) {
            const linked = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { bookId: true } });
            if (linked) {
              await tx.transaction.update({
                where: { id: txn.linkedTransactionId },
                data: { amount: finalAmount, category: 'Send', reconStatus: 'approved', counterProposedAmount: null, counterProposedBy: null }
              });
              // Adjust linked book balance
              await tx.book.update({
                where: { id: linked.bookId },
                data: { balance: { increment: amountDiff } }
              });
            }
          }

          // Update main transaction
          await tx.transaction.update({
            where: { id: txnId },
            data: { amount: finalAmount, reconStatus: 'approved', counterProposedAmount: null, counterProposedBy: null }
          });

          // Adjust source book balance for the difference
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
          return res.status(400).json({ error: 'Fund organization must approve the send first' });
        }

        const isSend = txn.category === 'Send' && txn.linkedTransactionId;
        if (isSend || (txn.category === 'Send' && (txn.recipientUserId || txn.recipientOrgId))) {
          const nextStatus = 'pending';

          // Send: advance fund_send chain (parallel org + recipient) or linked pair
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

          // Notify recipient that org approval passed
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
          // Check if it is a book-based voucher (transaction already in org's book)
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
                // Transaction is already in the org's book — just apply balance
                await tx.book.update({ where: { id: targetBook.id }, data: { balance: { decrement: txn.amount } } });
                // Sync the personal mirror to approved
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

          // General expense/voucher: approve directly with version lock
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

          // ── Apply Balance on Approval ──
          // Sender was already decremented on creation (balance counts even in pending).
          // Now only increment the receiver's income leg.
          if (txn.type === 'income') {
            await tx.book.update({ where: { id: txn.bookId }, data: { balance: { increment: txn.amount } } });
          } else if (txn.type === 'expense' && txn.linkedTransactionId) {
            // Sender already decremented on creation — no change.
            // Increment the linked income (receiver) if not yet approved.
            const linkedFull = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { type: true, bookId: true, amount: true } });
            if (linkedFull && linkedFull.type === 'income') {
              await tx.book.update({ where: { id: linkedFull.bookId }, data: { balance: { increment: linkedFull.amount } } });
            }
          }

          // ── Auto-adjustment: deduct existing approved deficits from new fund release ──
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

        // Broadcast deficit adjustment notification outside txn (non-critical)
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

      return res.status(400).json({ error: 'Transaction not eligible for approval' });
    } else {
      // REJECT
      if (txn.pendingAction) {
        const pd = txn.pendingData;
        const book = await prisma.book.findUnique({ where: { id: txn.bookId } });
        if (pd && book) {
          const pdObj = parsePendingData(pd);
          await prisma.$transaction(async (tx) => {
            // Restore balance using increment/decrement (GAP 2.3 fix)
            const balanceDelta = pd.oldType === 'expense' ? -pd.oldAmount : pd.oldAmount;
            await tx.book.update({
              where: { id: txn.bookId },
              data: { balance: { increment: balanceDelta } }
            });

            // Version-locked restore of main transaction
            const mainVer = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true } });
            if (!mainVer) throw new Error('Transaction not found');
            const upd = await tx.transaction.updateMany({
              where: { id: txnId, version: mainVer.version },
              data: {
                amount: pd.oldAmount, type: pd.oldType, category: pd.oldCategory,
                note: pd.oldNote, recipientUserId: pd.oldRecipientUserId || null,
                reconStatus: 'approved', pendingAction: null, pendingData: null,
                version: { increment: 1 }
              }
            });
            if (upd.count === 0) throw new Error('Concurrency conflict on pendingAction reject restore');

            const legs = await getCounterpartLegsForChangeDelete(txn, book, tx);
            for (const leg of legs) {
              if (!leg.pendingAction) continue;
              const legPd = parsePendingData(leg.pendingData || pd);
              const legDelta = legPd.oldType === 'expense' ? -legPd.oldAmount : legPd.oldAmount;
              await tx.book.update({
                where: { id: leg.bookId },
                data: { balance: { increment: legDelta } }
              });
              const legVer = await tx.transaction.findUnique({ where: { id: leg.id }, select: { version: true } });
              if (!legVer) continue;
              const updL = await tx.transaction.updateMany({
                where: { id: leg.id, version: legVer.version },
                data: {
                  amount: legPd.oldAmount,
                  type: legPd.oldType,
                  category: legPd.oldCategory,
                  note: legPd.oldNote,
                  reconStatus: 'approved',
                  pendingAction: null,
                  pendingData: null,
                  version: { increment: 1 }
                }
              });
              if (updL.count === 0) throw new Error('Concurrency conflict on counterpart pendingAction reject');
            }
          });

          // GAP 5: Notify requester that their edit/delete was rejected
          if (pdObj && pdObj.requestedBy) {
            const actionLabel = txn.pendingAction === 'edit' ? 'সম্পাদনা' : 'মুছে ফেলা';
            await createNotification(pdObj.requestedBy, txn.pendingAction === 'edit' ? 'EDIT_REJECTED' : 'DELETE_REJECTED', `${actionLabel} প্রত্যাখ্যান`, `আপনার অনুরোধ করা ${actionLabel} প্রত্যাখ্যান করা হয়েছে।`, txnId, null);
          }
        }
        broadcast({ type: "data_changed" });
        return res.json({ message: 'Changes rejected, original values restored' });
      }

      // Reject any pending state (pending_org, pending_recipient, pending)
      if (!['pending_org', 'pending_recipient', 'pending'].includes(txn.reconStatus)) {
        return res.status(400).json({ error: 'Transaction is not in a rejectable state' });
      }

    const book = await prisma.book.findUnique({ where: { id: txn.bookId } });
    if (!book) return res.status(404).json({ error: 'Book not found' });

    // Receiver can reject pending Send transactions
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

      // ── Deficit liability check ──
      // If rejecting a deficit chain where the recipient's income was already approved,
      // mark it as personal liability instead of rolling back the recipient's balance.
      let isLiabilityReject = false;
      if (txn.chainType === 'deficit' && txn.linkedTransactionId) {
        const linked = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
        if (linked && linked.reconStatus === 'approved') {
          isLiabilityReject = true;
        }
      }

      // Book-based voucher (pending_org with orgFundId): balance was NOT applied to org book on creation,
      // but the personal mirror had balance applied. Just mark rejected and reverse the mirror balance.
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

      // fund_send: reject entire chain atomically
      if (txn.chainType === 'fund_send' && txn.chainId) {
        await prisma.$transaction(async (tx) => {
          await rejectFundSendChain(tx, txn, rejectHistoryEntry);
        });
        broadcast({ type: 'data_changed' });
        return res.json({ message: 'Fund send rejected' });
      }

      // ── Atomic reject with linked transaction rollback ──
      await prisma.$transaction(async (tx) => {
        // Version-locked reject of main transaction
        const mainCurrent = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true, updateHistory: true } });
        if (!mainCurrent) throw new Error('Transaction not found');
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

        // Pending & pending_recipient: sender expense was decremented on creation, reverse it.
        // Approved: balance was fully applied, reverse it.
        // Income leg on pending: was NOT incremented on creation, no reversal needed.
        const shouldReverseMain = txn.type === 'expense' || txn.reconStatus === 'approved';
        if (shouldReverseMain) {
          const balanceAdjustment = txn.type === 'expense' ? txn.amount : -txn.amount;
          await tx.book.update({
            where: { id: txn.bookId },
            data: { balance: { increment: balanceAdjustment } }
          });
        }

        // Handle linked transaction
        if (txn.linkedTransactionId) {
          const linked = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
          if (linked) {
            const linkedVersion = linked.version;
            if (isLiabilityReject) {
              // Recipient already accepted → mark linked as liability, don't reverse its balance
              const updLink = await tx.transaction.updateMany({
                where: { id: txn.linkedTransactionId, version: linkedVersion },
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
              // Normal rollback: reject linked + reverse its balance atomically
              const updLink = await tx.transaction.updateMany({
                where: { id: txn.linkedTransactionId, version: linkedVersion },
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



        const orgSource = await resolveOrgSourceTxnForMirror(txn, tx);
        if (orgSource && orgSource.chainType !== 'fund_send') {
          await rejectCreatorPersonalMirror(tx, orgSource, rejectHistoryEntry);
        }
      });

      // Broadcast liability notification if applicable
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
    }
  } catch (error) {
    console.error('Transaction action error:', error);
    res.status(500).json({ error: 'Server error processing action' });
  }
});

};
