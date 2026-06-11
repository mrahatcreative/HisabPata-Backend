const { prisma } = require('../../../config/database');
const { broadcast } = require('../../../websocket');

const handleRejectModification = async (ctx) => {
  const { txn, txnId, req, res } = ctx;
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
};

const handleCounterApprove = async (ctx) => {
  const { txn, txnId, req, res, deps } = ctx;
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

  const sourceTxn = txn.type === 'expense' ? txn : linkedTxn;
  const recipientTxn = txn.type === 'income' ? txn : linkedTxn;

  const sourceDiff = sourceTxn.amount - finalAmount;
  const recipientDiff = finalAmount - recipientTxn.amount;

  await prisma.$transaction([
    prisma.transaction.update({
      where: { id: sourceTxn.id },
      data: {
        amount: finalAmount,
        reconStatus: 'approved',
        counterProposedAmount: null,
        counterProposedBy: null,
        updateHistory: [...(sourceTxn.updateHistory || []), ctx.approveHistoryEntry]
      }
    }),
    prisma.transaction.update({
      where: { id: recipientTxn.id },
      data: {
        amount: finalAmount,
        reconStatus: 'approved',
        counterProposedAmount: null,
        counterProposedBy: null,
        updateHistory: [...(recipientTxn.updateHistory || []), ctx.approveHistoryEntry]
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
};

module.exports = { handleRejectModification, handleCounterApprove };
