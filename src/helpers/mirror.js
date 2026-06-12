const { prisma } = require('../config/database');
const { CREATOR_PERSONAL_MIRROR_SUFFIX } = require('../config/constants');

const findCreatorPersonalMirror = async (orgTxn, txClient = prisma) => {
  if (!orgTxn?.clientRef) return null;
  return txClient.transaction.findFirst({
    where: { clientRef: orgTxn.clientRef + CREATOR_PERSONAL_MIRROR_SUFFIX }
  });
};

const findFundVoucherPairedTxn = async (txn, book, txClient = prisma) => {
  if (!txn?.clientRef) return null;
  let resolvedBook = book;
  if (!resolvedBook?.organization) {
    resolvedBook = await txClient.book.findUnique({
      where: { id: txn.bookId },
      include: { organization: true }
    });
  }
  if (!resolvedBook) return null;

  const cpm = await findCreatorPersonalMirror(txn, txClient);
  if (cpm) return cpm;

  if (resolvedBook.organization?.isPersonal && txn.orgFundId) {
    return txClient.transaction.findFirst({
      where: {
        bookId: txn.orgFundId,
        clientRef: txn.clientRef,
        createdById: txn.createdById
      }
    });
  }

  if (!resolvedBook.organization?.isPersonal) {
    return txClient.transaction.findFirst({
      where: {
        orgFundId: txn.bookId,
        clientRef: txn.clientRef,
        createdById: txn.createdById,
        book: { organization: { isPersonal: true } }
      }
    });
  }
  return null;
};

const getUserPersonalBook = async (userId, txClient = prisma) => {
  const membership = await txClient.organizationMember.findFirst({
    where: { userId, status: 'active', organization: { isPersonal: true } },
    include: { organization: { include: { books: { where: { isDefault: true }, take: 1 } } } }
  });
  return membership?.organization?.books?.[0] || null;
};

const createCreatorPersonalMirror = async (tx, {
  orgTxn,
  orgBook,
  creatorPersonalBook,
  userId,
  txnClientRef,
  mirrorType
}) => {
  if (!creatorPersonalBook || creatorPersonalBook.id === orgBook.id) return null;

  const type = mirrorType || orgTxn.type;
  const note = orgTxn.note || '';

  const mirror = await tx.transaction.create({
    data: {
      bookId: creatorPersonalBook.id,
      amount: orgTxn.amount,
      type,
      note,
      category: orgTxn.category,
      contact: orgTxn.contact,
      recipientUserId: orgTxn.recipientUserId || null,
      recipientOrgId: orgTxn.recipientOrgId || null,
      orgFundId: orgBook.id,
      createdById: userId,
      reconStatus: orgTxn.reconStatus,
      imageUrl: orgTxn.imageUrl,
      clientRef: txnClientRef + CREATOR_PERSONAL_MIRROR_SUFFIX,
      chainId: orgTxn.chainId || null,
      chainType: orgTxn.chainType || null,
      dateTime: orgTxn.dateTime || new Date()
    }
  });

  const balanceOp = type === 'income' ? { increment: orgTxn.amount } : { decrement: orgTxn.amount };
  await tx.book.update({ where: { id: creatorPersonalBook.id }, data: { balance: balanceOp } });
  return mirror;
};

const maybeMirrorOrgTxnToCreatorPersonal = async (tx, {
  orgTxn,
  orgBook,
  userId,
  txnClientRef,
  mirrorType,
  skipMirror = false
}) => {
  if (skipMirror || orgTxn.type !== 'expense' || orgBook.organization?.isPersonal || orgTxn.category === 'Send') return null;
  const personalBook = await getUserPersonalBook(userId, tx);
  if (!personalBook) return null;
  return createCreatorPersonalMirror(tx, {
    orgTxn,
    orgBook,
    creatorPersonalBook: personalBook,
    userId,
    txnClientRef,
    mirrorType
  });
};

const syncCreatorPersonalMirrorStatus = async (tx, orgTxn, status, historyEntry, extraData = {}) => {
  const mirror = await findCreatorPersonalMirror(orgTxn, tx);
  if (!mirror) return;
  const cur = await tx.transaction.findUnique({
    where: { id: mirror.id },
    select: { version: true, updateHistory: true }
  });
  if (!cur) return;
  const data = {
    reconStatus: status,
    version: { increment: 1 },
    ...extraData
  };
  if (historyEntry) {
    data.updateHistory = [...(cur.updateHistory || []), historyEntry];
  }
  await tx.transaction.updateMany({
    where: { id: mirror.id, version: cur.version },
    data
  });
};

const rejectCreatorPersonalMirror = async (tx, orgTxn, rejectHistoryEntry) => {
  const mirror = await findCreatorPersonalMirror(orgTxn, tx);
  if (!mirror || mirror.reconStatus === 'rejected') return;
  const cur = await tx.transaction.findUnique({
    where: { id: mirror.id },
    select: { version: true, updateHistory: true }
  });
  if (!cur) return;
  await tx.transaction.updateMany({
    where: { id: mirror.id, version: cur.version },
    data: {
      reconStatus: 'rejected',
      version: { increment: 1 },
      updateHistory: [...(cur.updateHistory || []), rejectHistoryEntry]
    }
  });

  const balanceAdj = mirror.type === 'expense' ? mirror.amount : -mirror.amount;
  await tx.book.update({
    where: { id: mirror.bookId },
    data: { balance: { increment: balanceAdj } }
  });
};

const resolveOrgSourceTxnForMirror = async (txn, txClient = prisma) => {
  const isRealOrgBook = async (bookId) => {
    const b = await txClient.book.findUnique({
      where: { id: bookId },
      include: { organization: { select: { isPersonal: true } } }
    });
    return b && !b.organization.isPersonal;
  };
  if (txn.type === 'expense' && await isRealOrgBook(txn.bookId)) return txn;
  if (txn.linkedTransactionId) {
    const linked = await txClient.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
    if (linked?.type === 'expense' && await isRealOrgBook(linked.bookId)) return linked;
  }
  return null;
};

module.exports = { findCreatorPersonalMirror, findFundVoucherPairedTxn, getUserPersonalBook, createCreatorPersonalMirror, maybeMirrorOrgTxnToCreatorPersonal, syncCreatorPersonalMirrorStatus, rejectCreatorPersonalMirror, resolveOrgSourceTxnForMirror };
