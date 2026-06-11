const { prisma } = require('../../config/database');
const { pickOrgRepresentative } = require('../access');
const { findFundVoucherPairedTxn } = require('../mirror');
const { parsePendingData, getOrgAdminUserIds } = require('../misc');
const {
  resolveChangeDeleteChain,
  getChangeDeleteCounterpartyUserId,
  txnHasLinkedChangeDeleteApproval,
} = require('./resolve');
const {
  getRequiredApproversForChangeDelete,
  getLinkedPartyUserIds,
} = require('./approvers');
const { computeRequiredApprovers } = require('./resolve');

const isChangeDeleteFullyApproved = (pendingData) => {
  const pd = parsePendingData(pendingData);
  const required = pd.requiredApprovers || [];
  const orgAnyOf = pd.orgApprovalAnyOf || [];
  const approvals = pd.approvals || [];
  const legApprovals = pd.legApprovals || [];

  if (pd.dualLegSameUser) {
    const otherLegId = pd.pairedTransactionId || pd.linkedTransactionId;
    const fromId = pd.requestedFromTxnId;
    if (otherLegId && fromId) {
      return legApprovals.includes(otherLegId) && !legApprovals.includes(fromId);
    }
    return false;
  }

  if (required.length === 0) return false;

  const nonOrgRequired = required.filter((id) => !orgAnyOf.includes(id));
  const orgRequired = required.some((id) => orgAnyOf.includes(id));
  const peopleOk = nonOrgRequired.every((id) => approvals.includes(id));
  const orgOk = !orgRequired || orgAnyOf.some((id) => approvals.includes(id));
  return peopleOk && orgOk;
};

const recordChangeDeleteApproval = (pendingData, approverId, approvingTxnId) => {
  const pd = parsePendingData(pendingData);
  const approvals = [...(pd.approvals || [])];
  if (!approvals.includes(approverId)) approvals.push(approverId);
  const legApprovals = [...(pd.legApprovals || [])];
  if (approvingTxnId && !legApprovals.includes(approvingTxnId)) legApprovals.push(approvingTxnId);
  return { ...pd, approvals, legApprovals };
};

const buildChangeDeletePendingData = async (txn, book, requesterId, baseData = {}) => {
  const chain = await resolveChangeDeleteChain(txn, book);
  let requiredApprovers = await getRequiredApproversForChangeDelete(txn, book, requesterId);
  const computed = computeRequiredApprovers(chain, requesterId);
  const { orgApprovalAnyOf, chainNote, isOrphan } = computed;
  if (requiredApprovers.length === 0 && computed.requiredApprovers?.length) {
    requiredApprovers = computed.requiredApprovers;
  }
  const partyIds = await getLinkedPartyUserIds(txn, book);
  const requester = await prisma.user.findUnique({ where: { id: requesterId }, select: { name: true } });
  const pairedFund = await findFundVoucherPairedTxn(txn, book);
  const dualLegSameUser =
    (requiredApprovers.length === 1 && requiredApprovers[0] === requesterId) ||
    (!!pairedFund && pairedFund.createdById === requesterId && txn.createdById === requesterId);

  let finalOrgApprovalAnyOf = orgApprovalAnyOf;
  if (finalOrgApprovalAnyOf.length === 0 && book.organizationId) {
    const org = await prisma.organization.findUnique({
      where: { id: book.organizationId },
      select: { isPersonal: true }
    });
    if (org && !org.isPersonal) {
      finalOrgApprovalAnyOf = requiredApprovers;
    }
  }

  return {
    ...baseData,
    requestedBy: requesterId,
    requesterName: requester?.name || 'Unknown',
    requestedFromTxnId: txn.id,
    linkedTransactionId: txn.linkedTransactionId || null,
    pairedTransactionId: pairedFund?.id || null,
    requiredApprovers,
    orgApprovalAnyOf: finalOrgApprovalAnyOf,
    approvals: [],
    legApprovals: [],
    partyCount: partyIds.length,
    requiredApprovalCount: requiredApprovers.length,
    chainNote,
    isOrphan: !!isOrphan && !txnHasLinkedChangeDeleteApproval(txn),
    dualLegSameUser,
  };
};

module.exports = {
  isChangeDeleteFullyApproved,
  recordChangeDeleteApproval,
  buildChangeDeletePendingData,
};
