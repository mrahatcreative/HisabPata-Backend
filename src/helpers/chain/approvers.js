const { prisma } = require('../../config/database');
const { checkApprovalBypass, userStillActive } = require('../access');
const { resolveOrgDisbursementOrgTxn } = require('../fund');
const { findFundVoucherPairedTxn } = require('../mirror');
const { getOrgAdminUserIds } = require('../misc');
const {
  txnHasLinkedChangeDeleteApproval,
  linkedBookExists,
  getChangeDeleteCounterpartyUserId,
  resolveChangeDeleteChain,
  computeRequiredApprovers,
} = require('./resolve');

const getLinkedPartyUserIds = async (txn, book) => {
  const chain = await resolveChangeDeleteChain(txn, book);
  if (chain.kind === 'p1_org_p2') {
    return [...new Set([chain.p1.userId, chain.p2.userId, ...chain.org.adminIds].filter(Boolean))];
  }
  if (chain.kind === 'p1_org') {
    return [...new Set([chain.p1.userId, ...chain.org.adminIds].filter(Boolean))];
  }
  if (chain.kind === 'p1_p2') {
    return [...new Set([chain.p1.userId, chain.p2.userId].filter(Boolean))];
  }
  return txn.createdById ? [txn.createdById] : [];
};

const getRequiredApproversForChangeDelete = async (txn, book, requesterId) => {
  let counterparty = await getChangeDeleteCounterpartyUserId(txn, book, requesterId);
  if (!counterparty && txn.linkedTransactionId) {
    const linked = await prisma.transaction.findUnique({
      where: { id: txn.linkedTransactionId },
      select: { createdById: true, recipientUserId: true },
    });
    if (linked?.createdById && linked.createdById !== requesterId) counterparty = linked.createdById;
    else if (linked?.recipientUserId && linked.recipientUserId !== requesterId) {
      counterparty = linked.recipientUserId;
    }
  }
  if (counterparty) return [counterparty];
  const chain = await resolveChangeDeleteChain(txn, book);
  const computed = computeRequiredApprovers(chain, requesterId);
  if (computed.requiredApprovers.length > 0) return computed.requiredApprovers;

  if (book.organizationId) {
    const org = await prisma.organization.findUnique({
      where: { id: book.organizationId },
      select: { isPersonal: true }
    });
    if (org && !org.isPersonal) {
      const bypass = await checkApprovalBypass(book.organizationId, requesterId);
      if (!bypass) {
        const admins = await prisma.organizationMember.findMany({
          where: {
            organizationId: book.organizationId,
            status: 'active',
            OR: [
              { role: 'admin' },
              { permissions: { has: 'edit_all' } }
            ]
          },
          select: { userId: true }
        });
        const adminIds = admins.map(a => a.userId).filter(id => id !== requesterId);
        if (adminIds.length > 0) {
          return adminIds;
        } else if (admins.length > 0) {
          return [requesterId];
        }
      }
    }
  }

  // Fallback: personal book mirrors linked to org fund require org admin approval
  if (book.organizationId && txn.orgFundId) {
    const bookOrg = await prisma.organization.findUnique({
      where: { id: book.organizationId },
      select: { isPersonal: true }
    });
    if (bookOrg?.isPersonal) {
      const fundBook = await prisma.book.findUnique({
        where: { id: txn.orgFundId },
        select: { organizationId: true }
      });
      if (fundBook?.organizationId) {
        const [fundOrg, fundMembers] = await Promise.all([
          prisma.organization.findUnique({
            where: { id: fundBook.organizationId },
            select: { isPersonal: true }
          }),
          prisma.organizationMember.findMany({
            where: {
              organizationId: fundBook.organizationId,
              status: 'active',
              OR: [{ role: 'admin' }, { permissions: { has: 'edit_all' } }]
            },
            select: { userId: true }
          })
        ]);
        if (fundOrg && !fundOrg.isPersonal) {
          const adminIds = fundMembers.map(m => m.userId);
          const filtered = adminIds.filter(id => id !== requesterId);
          if (filtered.length > 0) return filtered;
          if (adminIds.length > 0) return [requesterId];
        }
      }
    }
  }

  return [];
};

const mustUseChangeDeleteApprovalFlow = async (txn, book, requesterId) => {
  if (book.organizationId) {
    const org = await prisma.organization.findUnique({
      where: { id: book.organizationId },
      select: { isPersonal: true }
    });
    if (org && !org.isPersonal) {
      const bypass = await checkApprovalBypass(book.organizationId, requesterId);
      if (!bypass) {
        return true;
      }
    }
  }

  const pairedFund = await findFundVoucherPairedTxn(txn, book);
  if (
    txn.type === 'income' &&
    !txn.linkedTransactionId &&
    !txn.orgFundId &&
    !pairedFund &&
    txn.category !== 'Send' &&
    !txn.recipientUserId &&
    txn.chainType !== 'fund_send'
  ) {
    return false;
  }
  if (txn.linkedTransactionId) {
    const exists = await linkedBookExists(txn);
    if (!exists) return false;
  }
  if (txnHasLinkedChangeDeleteApproval(txn) || pairedFund) return true;
  const required = await getRequiredApproversForChangeDelete(txn, book, requesterId);
  return required.length > 0;
};

module.exports = {
  getLinkedPartyUserIds,
  getRequiredApproversForChangeDelete,
  mustUseChangeDeleteApprovalFlow,
};
