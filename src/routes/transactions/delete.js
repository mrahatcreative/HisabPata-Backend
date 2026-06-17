const { prisma } = require('../../config/database');
const { broadcast, broadcastToUser, broadcastToUsers } = require('../../websocket');

module.exports = function(app, deps) {
  const { authenticateToken, hasBookAccess, checkPermission, hasAdminOrEditorAccess, checkApprovalBypass, createNotification, getOrgAdminUserIds, maybeMirrorOrgTxnToCreatorPersonal, getChainRemainingBalance, mustUseChangeDeleteApprovalFlow, getRequiredApproversForChangeDelete, buildChangeDeletePendingData, syncCounterpartLegsForChangeDelete, notifyChangeDeleteApprovers, buildChangeDeleteNotification, deleteCounterpartLegsForChangeDelete, reverseTxnBalanceForRemoval, generateChainId, fundSendRetryStatuses, resolveApprovalOrgId, resolveFundSendChainParts, parsePendingData, parseClientDateTime, enrichTxn, DEFAULT_CATEGORIES } = deps;

// --- DELETE TRANSACTION ---
app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
  try {
    const txnId = req.params.id;

    const txn = await prisma.transaction.findUnique({ where: { id: txnId } });
    if (!txn) return res.status(404).json({ error: { bn: 'লেনদেন পাওয়া যায়নি।', en: 'Transaction not found' } });

    if (txn.reconStatus === 'FROZEN') {
      return res.status(422).json({ error: { bn: 'ফ্রোজেন লেনদেন মুছে ফেলা যাবে না। পুনরায় সংগঠনে যোগ দিন।', en: 'Frozen transaction cannot be deleted. Rejoin the organization to modify this entry.' } });
    }

    const book = await prisma.book.findUnique({ where: { id: txn.bookId } });
    if (!book) return res.status(404).json({ error: { bn: 'বই পাওয়া যায়নি।', en: 'Book not found' } });

    // ── Authorization: Who can delete? ──
    const isSender = txn.createdById === req.user.id;
    const isReceiver = txn.recipientUserId === req.user.id;
    const isSend = txn.category === 'Send';
    const isPending = txn.reconStatus === 'pending';
    const isApproved = txn.reconStatus === 'approved';
    const isRejected = txn.reconStatus === 'rejected';
    const isAdminOrEditor = await hasAdminOrEditorAccess(book.organizationId, req.user.id);

    if (isSend) {
      if (isPending) {
        if (isReceiver) {
          return res.status(403).json({ error: { bn: 'প্রাপক অপেক্ষমাণ লেনদেন মুছে ফেলতে পারবেন না।', en: 'Receiver cannot delete a pending transaction' } });
        }
        if (!isSender && !isAdminOrEditor) {
          return res.status(403).json({ error: { bn: 'শুধু প্রেরক, অ্যাডমিন বা এডিটর মুছে ফেলতে পারেন।', en: 'Only the sender, admins, or editors can delete' } });
        }
      } else if (isRejected) {
        if (!isSender && !isAdminOrEditor) {
          return res.status(403).json({ error: { bn: 'শুধু প্রেরক, অ্যাডমিন বা এডিটর প্রত্যাখ্যাত লেনদেন মুছে ফেলতে পারেন।', en: 'Only the sender, admins, or editors can delete a rejected transaction' } });
        }
      } else if (isApproved) {
        if (!isSender && !isReceiver && !isAdminOrEditor) {
          return res.status(403).json({ error: { bn: 'এই লেনদেন মুছে ফেলার অনুমতি নেই।', en: 'Not authorized to delete this transaction' } });
        }
      } else {
        if (!isAdminOrEditor) {
          return res.status(403).json({ error: { bn: 'শুধু অ্যাডমিন বা এডিটর লেনদেন মুছে ফেলতে পারেন।', en: 'Only admins or editors can delete transactions' } });
        }
      }
    } else {
      if (!isAdminOrEditor) {
        return res.status(403).json({ error: { bn: 'শুধু অ্যাডমিন বা এডিটর লেনদেন মুছে ফেলতে পারেন।', en: 'Only admins or editors can delete transactions' } });
      }
    }

    // If personal book txn has linked org txn, check if user is still a member of that org
    const bookOrg = await prisma.organization.findUnique({ where: { id: book.organizationId }, select: { isPersonal: true } });
    if (bookOrg?.isPersonal && txn.linkedTransactionId) {
      const linkedTxn = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { bookId: true } });
      if (linkedTxn) {
        const linkedBook = await prisma.book.findUnique({ where: { id: linkedTxn.bookId }, select: { organizationId: true } });
        if (linkedBook) {
          const linkedOrg = await prisma.organization.findUnique({ where: { id: linkedBook.organizationId }, select: { isPersonal: true } });
          if (linkedOrg && !linkedOrg.isPersonal) {
            const membership = await prisma.organizationMember.findUnique({
              where: { userId_organizationId: { userId: req.user.id, organizationId: linkedBook.organizationId } }
            });
            if (!membership || membership.status !== 'active') {
              return res.status(403).json({ error: { bn: 'সংগঠন থেকে leave করার পর এই entry delete করা যাবে না। আবার জয়েন করুন।', en: 'Cannot delete this entry after leaving the organization. Rejoin to modify.' } });
            }
          }
        }
      }
    }

    const user = await prisma.user.findUnique({ where: { id: req.user.id }, select: { name: true } });
    const org = bookOrg;
    if (txn.pendingAction) {
      return res.status(400).json({ error: { bn: 'লেনদেনটি ইতিমধ্যে একটি অপেক্ষমাণ কর্ম আছে।', en: 'Transaction already has a pending action' } });
    }

    // ── Determine delete type based on state ──
    let mustApprove = false;
    if (isSend) {
      if (isPending || isRejected) {
        // Pending/Rejected Send: direct delete, no balance reversal needed
        mustApprove = false;
      } else if (isApproved) {
        // Approved Send: pending delete, other party must approve
        mustApprove = true;
      } else {
        mustApprove = await mustUseChangeDeleteApprovalFlow(txn, book, req.user.id);
      }
    } else if (txn.reconStatus === 'pending_org' && txn.orgFundId) {
      // Book-based voucher: balance was never applied, direct delete without balance reversal
      mustApprove = false;
    } else {
      mustApprove = await mustUseChangeDeleteApprovalFlow(txn, book, req.user.id);
    }

    const requiredApprovers = await getRequiredApproversForChangeDelete(txn, book, req.user.id);
    if (mustApprove && requiredApprovers.length === 0) {
      mustApprove = false;
    }
    if (txn.reconStatus === 'rejected' && !isSend) {
      mustApprove = false;
    }

    const executeHardDelete = async () => {
      await prisma.$transaction(async (prisma) => {
        let balanceAdjustment = reverseTxnBalanceForRemoval(txn);
        if (!isSend && txn.reconStatus === 'rejected') {
          balanceAdjustment = 0;
        }

        if (balanceAdjustment !== 0) {
          await prisma.book.update({ where: { id: book.id }, data: { balance: { increment: balanceAdjustment } } });
        }
        await deleteCounterpartLegsForChangeDelete(prisma, txn, book);
        await prisma.transaction.delete({ where: { id: txnId } });
      });
      broadcast({ type: 'data_changed' });
    };

    if (!mustApprove) {
      await executeHardDelete();
      const recipientId = txn.recipientUserId;
      if (recipientId && recipientId !== req.user.id) {
        await createNotification(recipientId, 'DELETE_COMPLETED', 'লেনদেন মুছে ফেলা হয়েছে', `${user?.name || 'কেউ'} একটি লেনদেন মুছে ফেলেছেন।`, txnId, book.organizationId);
      }
      return res.json({ message: 'Transaction deleted', pending: false });
    }

    // Approved Send: transition to pending delete
    const pendingData = await buildChangeDeletePendingData(txn, book, req.user.id, {
      oldAmount: txn.amount,
      oldType: txn.type,
      oldCategory: txn.category,
      oldNote: txn.note,
      oldRecipientUserId: txn.recipientUserId,
      oldLinkedTransactionId: txn.linkedTransactionId,
      oldOrgFundId: txn.orgFundId,
    });

    await prisma.$transaction(async (prisma) => {
      // Don't change reconStatus (stays 'approved'), just set pendingAction
      await prisma.transaction.update({
        where: { id: txnId },
        data: {
          pendingAction: 'delete',
          pendingData,
          updateHistory: [
            ...(txn.updateHistory || []),
            {
              timestamp: new Date().toISOString(),
              userId: req.user.id,
              userName: user?.name || 'Unknown',
              action: 'delete_request',
              changes: { old: { amount: txn.amount, type: txn.type, category: txn.category, note: txn.note } },
            },
          ],
        },
      });

      // For Send transactions: don't reverse balance during pending delete
      // (balance stays effective until delete is finally approved)
      if (!isSend && txn.reconStatus !== 'rejected') {
        const balanceAdj = txn.type === 'expense' ? txn.amount : -txn.amount;
        await prisma.book.update({
          where: { id: book.id },
          data: { balance: { increment: balanceAdj } },
        });
      }

      await syncCounterpartLegsForChangeDelete(prisma, txn, book, {
        pendingAction: 'delete',
        pendingData,
        historyEntry: {
          timestamp: new Date().toISOString(),
          userId: req.user.id,
          userName: user?.name || 'Unknown',
          action: 'delete_request (counterpart)',
          changes: { old: { amount: txn.amount, type: txn.type, category: txn.category, note: txn.note } }
        },
        reverseBalanceOnRequest: !isSend, // Don't reverse balance for Send during pending
        keepReconStatus: isSend, // Send stays 'approved', uses pendingAction
      }, req.user.id);
    });

    broadcast({ type: 'data_changed' });
    const refreshedTxn = await prisma.transaction.findUnique({ where: { id: txnId } });
    await notifyChangeDeleteApprovers(refreshedTxn || txn, 'delete', pendingData);
    const summary = buildChangeDeleteNotification(pendingData, 'delete', refreshedTxn || txn);
    const enriched = refreshedTxn ? await enrichTxn(refreshedTxn) : null;
    return res.json({
      message: 'Delete request submitted for approval',
      pending: true,
      notification: summary,
      transaction: enriched
    });
  } catch (error) {
    console.error('Delete transaction error:', error);
    res.status(500).json({ error: 'Server error deleting transaction' });
  }
});

// ── PERMANENT DELETE a transaction (hard delete from DB) ──
app.delete('/api/transactions/:id/permanent', authenticateToken, async (req, res) => {
  try {
    const txnId = req.params.id;
    const txn = await prisma.transaction.findUnique({ where: { id: txnId } });
    if (!txn) return res.status(404).json({ error: { bn: 'লেনদেন পাওয়া যায়নি।', en: 'Transaction not found' } });

    const book = await prisma.book.findUnique({ where: { id: txn.bookId } });
    if (!book) return res.status(404).json({ error: { bn: 'বই পাওয়া যায়নি।', en: 'Book not found' } });

    if (!(await hasAdminOrEditorAccess(book.organizationId, req.user.id))) {
      return res.status(403).json({ error: { bn: 'শুধু অ্যাডমিন বা এডিটর স্থায়ীভাবে লেনদেন মুছে ফেলতে পারেন।', en: 'Only admins or editors can permanently delete transactions' } });
    }

    await prisma.$transaction(async (tx) => {
      const isSendLocal = txn.category === 'Send';
      const alreadyReversed = (!isSendLocal && txn.reconStatus === 'rejected') || txn.reconStatus === 'delete_rejected' || !!txn.pendingAction;
      if (!alreadyReversed) {
        const balanceAdj = txn.type === 'expense' ? txn.amount : -txn.amount;
        await tx.book.update({
          where: { id: txn.bookId },
          data: { balance: { increment: balanceAdj } }
        });
      }

      // Delete linked transaction first if exists
      if (txn.linkedTransactionId) {
        const linked = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
        if (linked) {
          const linkedIsSend = linked.category === 'Send';
          const linkedAlreadyReversed = (!linkedIsSend && linked.reconStatus === 'rejected') || linked.reconStatus === 'delete_rejected' || !!linked.pendingAction;
          if (!linkedAlreadyReversed) {
            const linkedBalanceAdj = linked.type === 'income' ? -linked.amount : linked.amount;
            await tx.book.update({
              where: { id: linked.bookId },
              data: { balance: { increment: linkedBalanceAdj } }
            });
          }
          await tx.transaction.delete({ where: { id: txn.linkedTransactionId } });
        }
      }

      await tx.transaction.delete({ where: { id: txnId } });
    });

    broadcast({ type: "data_changed" });
    return res.json({ message: 'Transaction permanently deleted' });
  } catch (error) {
    console.error('Permanent delete error:', error);
    res.status(500).json({ error: 'Server error permanently deleting transaction' });
  }
});
};
