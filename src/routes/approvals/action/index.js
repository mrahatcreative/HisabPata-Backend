const { prisma } = require('../../../config/database');
const {
  checkApprovalBypass,
  hasAdminOrEditorAccess,
  checkPermission,
} = require('../../../helpers/index');
const { handleApprove } = require('./approve');
const { handleReject } = require('./reject');
const { handleRejectModification, handleCounterApprove } = require('./counter');

module.exports = function(app, deps) {
  const { authenticateToken, createNotification, getOrgAdminUserIds, parsePendingData } = deps;

  app.post('/api/transactions/:id/action', authenticateToken, async (req, res) => {
    try {
      const { action } = req.body;

      if (!['approve', 'reject', 'counter_approve', 'reject_modification'].includes(action)) {
        return res.status(400).json({ error: 'Action must be "approve", "reject", "counter_approve", or "reject_modification"' });
      }

      const txn = await prisma.transaction.findUnique({ where: { id: req.params.id } });
      if (!txn) return res.status(404).json({ error: 'Transaction not found' });

      // Prevent double approval of already approved transaction
      if (action === 'approve' && txn.reconStatus === 'approved' && !txn.pendingAction && txn.counterProposedAmount == null) {
        return res.json({ transaction: txn, message: 'Transaction is already approved' });
      }

      const txnBook = await prisma.book.findUnique({ where: { id: txn.bookId } });
      if (!txnBook) return res.status(404).json({ error: 'Book not found' });

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

      const ctx = { txn, txnId: req.params.id, txnBook, book: txnBook, user, req, res, deps, userName, approveHistoryEntry, rejectHistoryEntry };

      switch (action) {
        case 'approve':
          return await handleApprove(ctx);
        case 'reject':
          return await handleReject(ctx);
        case 'counter_approve':
          return await handleCounterApprove(ctx);
        case 'reject_modification':
          return await handleRejectModification(ctx);
        default:
          return res.status(400).json({ error: 'Invalid action' });
      }
    } catch (error) {
      console.error('Transaction action error:', error);
      res.status(500).json({ error: 'Server error processing action' });
    }
  });
};
