const { prisma } = require('../../../config/database');
const { broadcast } = require('../../../websocket');
const { enrichTxn } = require('../../../helpers/enrichTxn');

module.exports = async (ctx) => {
  const { book, parsedAmount, txnClientRef, txnDateTime, computedFundType, deps, req, res } = ctx;
  const { checkApprovalBypass, maybeMirrorOrgTxnToCreatorPersonal } = deps;
  const { note, contact, fromLocation, toLocation, imageUrl, bookId, type } = req.body;

  const balanceOp = type === 'income' ? { increment: parsedAmount } : { decrement: parsedAmount };

  let initialStatus = 'approved';
  if (type === 'expense' && !book.organization.isPersonal) {
    const bypass = await checkApprovalBypass(book.organizationId, req.user.id);
    initialStatus = bypass ? 'approved' : 'pending_org';
  }

  const createResult = await prisma.$transaction(async (tx) => {
    const transaction = await tx.transaction.create({
      data: { bookId, amount: parsedAmount, type, note, category: req.body.category, contact, fundType: computedFundType, fromLocation, toLocation, createdById: req.user.id, reconStatus: initialStatus, imageUrl, clientRef: txnClientRef, dateTime: txnDateTime }
    });
    await tx.book.update({ where: { id: bookId }, data: { balance: balanceOp } });
    await maybeMirrorOrgTxnToCreatorPersonal(tx, {
      orgTxn: transaction,
      orgBook: book,
      userId: req.user.id,
      txnClientRef
    });
    const updatedBook = await tx.book.findUnique({ where: { id: bookId } });
    return { transaction, updatedBook };
  });

  broadcast({ type: "data_changed" });
  const enriched = await enrichTxn(createResult.transaction);
  res.status(201).json({ transaction: enriched, book: createResult.updatedBook });
};
