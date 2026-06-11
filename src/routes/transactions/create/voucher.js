const { prisma } = require('../../../config/database');
const { broadcast, broadcastToUser, broadcastToUsers } = require('../../../websocket');
const { enrichTxn } = require('../../../helpers/enrichTxn');

module.exports = async (ctx) => {
  const { book, parsedAmount, txnClientRef, txnDateTime, computedFundType, deps, req, res } = ctx;
  const { checkApprovalBypass, hasAdminOrEditorAccess, checkPermission, createNotification, getOrgAdminUserIds, maybeMirrorOrgTxnToCreatorPersonal } = deps;
  const { note, contact, fromLocation, toLocation, imageUrl, orgFundId } = req.body;

  let isVoucherTxn = false;
  let isVoucherBook = false;
  let targetBook = null;
  let origDisbursement = null;

  origDisbursement = await prisma.transaction.findUnique({ where: { id: orgFundId } });
  if (origDisbursement) {
    isVoucherTxn = true;
  } else {
    targetBook = await prisma.book.findUnique({ where: { id: orgFundId } });
    if (targetBook) {
      isVoucherBook = true;
    } else {
      return res.status(404).json({ error: 'Original disbursement or target book not found' });
    }
  }

  const voucherOrgBook = isVoucherTxn
    ? await prisma.book.findUnique({ where: { id: origDisbursement.bookId } })
    : targetBook;
  if (!voucherOrgBook) {
    return res.status(400).json({ error: 'Target organization book not found' });
  }

  if (voucherOrgBook.organizationId) {
    const voucherOrgMember = await prisma.organizationMember.findFirst({
      where: { userId: req.user.id, organizationId: voucherOrgBook.organizationId, status: 'active' }
    });
    if (!voucherOrgMember) {
      return res.status(403).json({ error: 'Not a member of the target organization' });
    }
  }

  const txn = await prisma.transaction.create({
    data: {
      bookId: voucherOrgBook.id,
      amount: parsedAmount,
      type: 'expense',
      note,
      category: req.body.category,
      contact,
      orgFundId: isVoucherTxn ? origDisbursement.bookId : targetBook.id,
      fundType: computedFundType,
      fromLocation,
      toLocation,
      createdById: req.user.id,
      reconStatus: 'pending_org',
      imageUrl,
      clientRef: txnClientRef,
      dateTime: txnDateTime
    }
  });

  await maybeMirrorOrgTxnToCreatorPersonal(prisma, {
    orgTxn: txn,
    orgBook: voucherOrgBook,
    userId: req.user.id,
    txnClientRef
  });

  const orgAdmins = await prisma.organizationMember.findMany({
    where: { organizationId: voucherOrgBook.organizationId, status: 'active', OR: [{ role: 'admin' }, { permissions: { has: 'edit_all' } }] },
    select: { userId: true }
  });
  const adminIds = orgAdmins.map(a => a.userId);
  broadcastToUsers(adminIds, { type: 'pending_voucher', transaction: txn });
  for (const uid of adminIds) {
    await createNotification(uid, 'VOUCHER_PENDING', 'নতুন খরচ অনুমোদন প্রয়োজন', `${req.user.name || 'কেউ'} ${parsedAmount} টাকার একটি খরচ এন্ট্রি জমা দিয়েছে।`, txn.id, voucherOrgBook.organizationId);
  }

  broadcast({ type: "data_changed" });
  const enriched = await enrichTxn(txn);
  return res.status(201).json({ transaction: enriched, book: await prisma.book.findUnique({ where: { id: voucherOrgBook.id } }), isVoucher: true });
};
