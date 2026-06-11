const { prisma } = require('../config/database');
const { broadcast } = require('../websocket');

module.exports = function(app, { authenticateToken, resolveApprovalOrgId, checkApprovalBypass, resolveFundSendChainParts, fundSendRetryStatuses, hasAdminOrEditorAccess }) {

// ── RETRY a rejected transaction: create a fresh submission from old data ──
app.post('/api/transactions/:id/retry', authenticateToken, async (req, res) => {
  try {
    const txnId = req.params.id;
    const txn = await prisma.transaction.findUnique({ where: { id: txnId } });
    if (!txn) return res.status(404).json({ error: 'Transaction not found' });
    if (txn.reconStatus !== 'rejected') {
      return res.status(400).json({ error: 'Only rejected transactions can be retried' });
    }

    // Accept updated fields from body (PRD section 16: retry with updated data)
    const retryUpdates = {};
    if (req.body.amount !== undefined) {
      const parsed = parseFloat(req.body.amount);
      if (!Number.isFinite(parsed) || parsed <= 0) return res.status(400).json({ error: 'Amount must be a valid positive number' });
      retryUpdates.amount = parsed;
    }
    if (req.body.note !== undefined) retryUpdates.note = req.body.note;
    if (req.body.description !== undefined) retryUpdates.note = req.body.description;
    if (req.body.category !== undefined) retryUpdates.category = req.body.category;
    if (req.body.fromLocation !== undefined) retryUpdates.fromLocation = req.body.fromLocation;
    if (req.body.toLocation !== undefined) retryUpdates.toLocation = req.body.toLocation;

    const book = await prisma.book.findUnique({ where: { id: txn.bookId }, include: { organization: true } });
    if (!book) return res.status(404).json({ error: 'Book not found' });

    const approvalOrgId = await resolveApprovalOrgId(txn, book);
    const bypassOrgApproval = await checkApprovalBypass(approvalOrgId, req.user.id);
    const isSend = txn.category === 'Send';
    const newStatus = isSend
      ? 'pending'
      : (bypassOrgApproval ? 'approved' : 'pending_org');

    const updated = await prisma.$transaction(async (tx) => {
      const main = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true } });
      if (!main) throw new Error('Transaction not found');

      if (txn.chainType === 'fund_send' && txn.chainId) {
        const chainTxns = await tx.transaction.findMany({ where: { chainId: txn.chainId } });
        const { personalTxn, fundOrgTxn, recipientTxn } = resolveFundSendChainParts(chainTxns);
        const isSelfSend = personalTxn?.recipientUserId === personalTxn?.createdById;
        const statuses = fundSendRetryStatuses(bypassOrgApproval, isSelfSend);

        for (const ct of chainTxns) {
          const targetStatus =
            ct.id === recipientTxn?.id ? statuses.recipient
            : ct.id === fundOrgTxn?.id ? statuses.fundOrg
            : statuses.personal;
          const cur = await tx.transaction.findUnique({ where: { id: ct.id }, select: { version: true } });
          const updC = await tx.transaction.updateMany({
            where: { id: ct.id, version: cur.version },
            data: {
              reconStatus: targetStatus,
              ...retryUpdates,
              pendingAction: null,
              pendingData: null,
              counterProposedAmount: null,
              counterProposedBy: null,
              isLiability: false,
              version: { increment: 1 }
            }
          });
          if (updC.count === 0) throw new Error('Concurrency conflict on fund_send retry');
        }

        for (const ct of chainTxns) {
          // Do not increment recipient balance for pending_recipient
          if (ct.type === 'income') continue;
          
          const balanceDelta = ct.type === 'expense' ? -ct.amount : ct.amount;
          await tx.book.update({
            where: { id: ct.bookId },
            data: { balance: { increment: balanceDelta } }
          });
        }
      } else {
        const upd = await tx.transaction.updateMany({
          where: { id: txnId, version: main.version },
          data: {
            reconStatus: newStatus,
            ...retryUpdates,
            pendingAction: null,
            pendingData: null,
            counterProposedAmount: null,
            counterProposedBy: null,
            version: { increment: 1 }
          }
        });
        if (upd.count === 0) throw new Error('Concurrency conflict on retry');

      if (txn.linkedTransactionId) {
        const linked = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { version: true } });
        if (linked) {
          const updL = await tx.transaction.updateMany({
            where: { id: txn.linkedTransactionId, version: linked.version },
            data: {
              reconStatus: newStatus,
              ...retryUpdates,
              pendingAction: null,
              pendingData: null,
              counterProposedAmount: null,
              counterProposedBy: null,
              isLiability: false,
              version: { increment: 1 }
            }
          });
          if (updL.count === 0) throw new Error('Concurrency conflict on linked retry');
        }

        // Send transactions: no balance change on retry.
        // Balance is applied atomically when the receiver approves.
        // This ensures deterministic balance for both old (pending_recipient)
        // and new (pending) flows.
      }
      }



      // Re-apply balance (reject had reversed it) for non-send expenses
      if (!isSend) {
        const balanceDelta = txn.type === 'expense' ? -txn.amount : txn.amount;
        await tx.book.update({
          where: { id: txn.bookId },
          data: { balance: { increment: balanceDelta } }
        });



        // Bypass on fund org: mirror expense into org book (same as create voucher flow)
        if (bypassOrgApproval && newStatus === 'approved' && txn.orgFundId) {
          const targetBook = await tx.book.findUnique({ where: { id: txn.orgFundId } });
          if (targetBook && targetBook.id !== txn.bookId) {
            await tx.book.update({
              where: { id: targetBook.id },
              data: { balance: { decrement: txn.amount } }
            });
            await tx.transaction.create({
              data: {
                bookId: targetBook.id,
                amount: txn.amount,
                type: 'expense',
                note: txn.note || '',
                category: txn.category || 'Voucher',
                contact: txn.contact,
                orgFundId: targetBook.id,
                createdById: txn.createdById,
                reconStatus: 'approved',
                clientRef: txn.clientRef,
                imageUrl: txn.imageUrl
              }
            });
          }
        }
      }

      return tx.transaction.findUnique({ where: { id: txnId } });
    });

    broadcast({ type: "data_changed" });
    const enriched = await (async (txn) => {
      let recipientName = null;
      if (txn.recipientUserId) {
        const u = await prisma.user.findUnique({ where: { id: txn.recipientUserId }, select: { name: true } });
        recipientName = u?.name || null;
      }
      return { ...txn, recipientName };
    })(updated);

    return res.json({ transaction: enriched, message: 'Transaction retried, sent for approval again' });
  } catch (error) {
    console.error('Retry transaction error:', error);
    res.status(500).json({ error: 'Server error retrying transaction' });
  }
});

};
