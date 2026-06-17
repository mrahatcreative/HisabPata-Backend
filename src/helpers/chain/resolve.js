const { prisma } = require('../../config/database');
const { CREATOR_PERSONAL_MIRROR_SUFFIX } = require('../../config/constants');
const { userStillActive, pickOrgRepresentative } = require('../access');
const { resolveOrgDisbursementOrgTxn } = require('../fund');
const { findCreatorPersonalMirror, findFundVoucherPairedTxn } = require('../mirror');
const { getOrgAdminUserIds } = require('../misc');

const txnHasLinkedChangeDeleteApproval = (txn) =>
  !!(
    txn.linkedTransactionId ||
    txn.category === 'Send' ||
    txn.chainType === 'fund_send' ||
    txn.recipientUserId ||
    txn.orgFundId
  );

const linkedBookExists = async (txn) => {
  if (!txn.linkedTransactionId) return true;
  const linkedTxn = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { bookId: true } });
  if (!linkedTxn) return false;
  const book = await prisma.book.findUnique({ where: { id: linkedTxn.bookId }, select: { isActive: true } });
  return book?.isActive === true;
};

const getChangeDeleteCounterpartyUserId = async (txn, book, requesterId) => {
  const disbursement = await resolveOrgDisbursementOrgTxn(txn, book);
  if (disbursement) {
    const { orgTxn } = disbursement;
    const onOrgExpenseLeg =
      txn.id === orgTxn.id ||
      (txn.bookId === orgTxn.bookId && txn.type === 'expense' && txn.category === 'Send');
    if (onOrgExpenseLeg) return orgTxn.recipientUserId || null;
    if (txn.type === 'income' && txn.category === 'Send') return orgTxn.createdById || null;
    if (requesterId === orgTxn.createdById) return orgTxn.recipientUserId || null;
    if (requesterId === orgTxn.recipientUserId) return orgTxn.createdById || null;
    return orgTxn.recipientUserId || orgTxn.createdById || null;
  }

  const pairedFund = await findFundVoucherPairedTxn(txn, book);
  if (pairedFund) {
    let resolvedBook = book;
    if (!resolvedBook?.organization) {
      resolvedBook = await prisma.book.findUnique({
        where: { id: txn.bookId },
        include: { organization: true }
      });
    }
    if (resolvedBook?.organization?.isPersonal && txn.orgFundId) {
      const fundBook = await prisma.book.findUnique({ where: { id: txn.orgFundId } });
      if (fundBook?.organizationId) {
        const adminIds = await getOrgAdminUserIds(fundBook.organizationId);
        const rep = pickOrgRepresentative(adminIds, requesterId);
        if (rep) return rep;
      }
    } else if (!resolvedBook?.organization?.isPersonal) {
      if (pairedFund.createdById && pairedFund.createdById !== requesterId) return pairedFund.createdById;
      if (txn.createdById && txn.createdById !== requesterId) return txn.createdById;
    }
  }

  if (txn.linkedTransactionId) {
    const linked = await prisma.transaction.findUnique({
      where: { id: txn.linkedTransactionId },
      select: { id: true, createdById: true, recipientUserId: true },
    });
    if (linked) {
      if (linked.createdById && linked.createdById !== requesterId) return linked.createdById;
      if (linked.recipientUserId && linked.recipientUserId !== requesterId) return linked.recipientUserId;
      if (txn.recipientUserId && txn.recipientUserId !== requesterId) return txn.recipientUserId;
      if (txn.createdById && txn.createdById !== requesterId) return txn.createdById;
    }
  }

  if (txn.recipientUserId && txn.recipientUserId !== requesterId) return txn.recipientUserId;
  if (txn.createdById && txn.createdById !== requesterId) return txn.createdById;
  return null;
};

const finalizeLinkedChangeDeleteApprovers = (candidateIds, requesterId, chain) => {
  let required = [...new Set(candidateIds.filter((id) => id && id !== requesterId))];
  const dualLegs =
    chain.p1?.hasEntry &&
    chain.p2?.hasEntry &&
    chain.p1?.active &&
    chain.p2?.active &&
    chain.p1?.userId &&
    chain.p1.userId === chain.p2?.userId;
  if (required.length === 0 && dualLegs) {
    required = [chain.p2.userId];
  }
  return required;
};

const buildP1OrgApprovers = (chain, requesterId) => {
  const requesterIsP1 = requesterId === chain.p1.userId;
  const requesterIsOrg = chain.org.adminIds.includes(requesterId);
  if (requesterIsP1) {
    const rep = pickOrgRepresentative(chain.org.adminIds, requesterId);
    if (rep) {
      return { requiredApprovers: [rep], orgApprovalAnyOf: chain.org.adminIds.filter(id => id !== requesterId), chainNote: 'degraded_p1_org' };
    }
    // Sender is the only admin of the org — keep them as required approver
    // so the request goes through pending flow (not instant delete).
    return { requiredApprovers: chain.org.adminIds, orgApprovalAnyOf: [], chainNote: 'degraded_p1_org' };
  }
  if (requesterIsOrg) {
    return {
      requiredApprovers: chain.p1.userId && chain.p1.userId !== requesterId ? [chain.p1.userId] : [],
      orgApprovalAnyOf: [],
      chainNote: 'degraded_p1_org',
    };
  }
  const rep = pickOrgRepresentative(chain.org.adminIds, requesterId);
  return { requiredApprovers: rep ? [rep] : chain.org.adminIds.filter(id => id !== requesterId), orgApprovalAnyOf: chain.org.adminIds.filter(id => id !== requesterId), chainNote: 'degraded_p1_org' };
};

const computeRequiredApprovers = (chain, requesterId) => {
  if (!chain || chain.kind === 'solo') {
    return { requiredApprovers: [], orgApprovalAnyOf: [], chainNote: 'solo', isOrphan: true };
  }

  if (chain.kind === 'p1_org') {
    const p1Ok = chain.p1.active && chain.p1.hasEntry;
    const orgOk = chain.org.active && chain.org.hasEntry;
    if (!p1Ok || !orgOk) {
      return { requiredApprovers: [], orgApprovalAnyOf: [], chainNote: 'orphan_dual', isOrphan: true };
    }
    const result = buildP1OrgApprovers(chain, requesterId);
    return { ...result, isOrphan: false };
  }

  if (chain.kind === 'p1_p2') {
    const p1Ok = chain.p1.active && chain.p1.hasEntry;
    const p2Ok = chain.p2.active && chain.p2.hasEntry;
    if (!p1Ok || !p2Ok) {
      return { requiredApprovers: [], orgApprovalAnyOf: [], chainNote: 'orphan_dual', isOrphan: true };
    }
    const otherId = requesterId === chain.p1.userId ? chain.p2.userId : chain.p1.userId;
    return {
      requiredApprovers: finalizeLinkedChangeDeleteApprovers(otherId ? [otherId] : [], requesterId, chain),
      orgApprovalAnyOf: [],
      chainNote: 'dual',
      isOrphan: false,
    };
  }

  if (chain.kind === 'p1_org_p2') {
    const p1Ok = chain.p1.active && chain.p1.hasEntry;
    const p2Ok = chain.p2.active && chain.p2.hasEntry;
    const orgOk = chain.org.active && chain.org.hasEntry;
    const presentLegs = [p1Ok, p2Ok, orgOk].filter(Boolean).length;

    if (presentLegs <= 1) {
      return { requiredApprovers: [], orgApprovalAnyOf: [], chainNote: 'orphan_triple', isOrphan: true };
    }

    if (!orgOk) {
      if (p1Ok && p2Ok) {
        const otherId = requesterId === chain.p1.userId ? chain.p2.userId : chain.p1.userId;
        return {
          requiredApprovers: finalizeLinkedChangeDeleteApprovers(otherId ? [otherId] : [], requesterId, chain),
          orgApprovalAnyOf: [],
          chainNote: 'degraded_p1_p2',
          isOrphan: false,
        };
      }
      return { requiredApprovers: [], orgApprovalAnyOf: [], chainNote: 'orphan_triple', isOrphan: true };
    }

    if (!p2Ok || !chain.p2.active) {
      if (!p1Ok) {
        return { requiredApprovers: [], orgApprovalAnyOf: [], chainNote: 'orphan_triple', isOrphan: true };
      }
      const result = buildP1OrgApprovers(chain, requesterId);
      return { ...result, isOrphan: false };
    }

    if (!p1Ok || !chain.p1.active) {
      if (!p2Ok) {
        return { requiredApprovers: [], orgApprovalAnyOf: [], chainNote: 'orphan_triple', isOrphan: true };
      }
      const requesterIsP2 = requesterId === chain.p2.userId;
      const requesterIsOrg = chain.org.adminIds.includes(requesterId);
      if (requesterIsP2) {
        const rep = pickOrgRepresentative(chain.org.adminIds, requesterId);
        return { requiredApprovers: rep ? [rep] : chain.org.adminIds, orgApprovalAnyOf: chain.org.adminIds, chainNote: 'degraded_org_p2', isOrphan: false };
      }
      if (requesterIsOrg) {
        return {
          requiredApprovers: finalizeLinkedChangeDeleteApprovers(
            [chain.p1.userId, chain.p2.userId].filter(Boolean),
            requesterId,
            chain
          ),
          orgApprovalAnyOf: [],
          chainNote: 'degraded_org_p2',
          isOrphan: false,
        };
      }
      const rep = pickOrgRepresentative(chain.org.adminIds, requesterId);
      let reqs = [chain.p2.userId, rep].filter((id) => id && id !== requesterId);
      return {
        requiredApprovers: reqs,
        orgApprovalAnyOf: chain.org.adminIds,
        chainNote: 'degraded_org_p2',
        isOrphan: false,
      };
    }

    const required = [];
    const requesterIsP1 = requesterId === chain.p1.userId;
    const requesterIsP2 = requesterId === chain.p2.userId;
    const requesterIsOrg = chain.org.adminIds.includes(requesterId);

    if (requesterIsP1) {
      if (chain.p2.userId) required.push(chain.p2.userId);
      const rep = pickOrgRepresentative(chain.org.adminIds, requesterId);
      if (rep) required.push(rep);
    } else if (requesterIsP2) {
      if (chain.p1.userId) required.push(chain.p1.userId);
      const rep = pickOrgRepresentative(chain.org.adminIds, requesterId);
      if (rep) required.push(rep);
    } else if (requesterIsOrg) {
      if (chain.p1.userId) required.push(chain.p1.userId);
      if (chain.p2.userId) required.push(chain.p2.userId);
    } else {
      if (chain.p1.userId) required.push(chain.p1.userId);
      if (chain.p2.userId) required.push(chain.p2.userId);
    }

    let reqs = finalizeLinkedChangeDeleteApprovers(required, requesterId, chain);
    return {
      requiredApprovers: reqs,
      orgApprovalAnyOf: chain.org.adminIds,
      chainNote: 'triple',
      isOrphan: false,
    };
  }

  return { requiredApprovers: [], orgApprovalAnyOf: [], chainNote: 'solo', isOrphan: true };
};

const resolveChangeDeleteChain = async (txn, book) => {
  let resolvedBook = book;
  if (!resolvedBook?.organization) {
    resolvedBook = await prisma.book.findUnique({
      where: { id: txn.bookId },
      include: { organization: true },
    });
  }
  if (!resolvedBook) return { kind: 'solo' };

  const disbursement = await resolveOrgDisbursementOrgTxn(txn, resolvedBook);
  if (disbursement) {
    const { orgTxn, orgBook } = disbursement;
    const org = orgBook?.organizationId
      ? await prisma.organization.findUnique({ where: { id: orgBook.organizationId } })
      : null;
    const orgAdminIds = org ? await getOrgAdminUserIds(orgBook.organizationId) : [];
    const personalTxn = orgTxn.linkedTransactionId
      ? await prisma.transaction.findUnique({ where: { id: orgTxn.linkedTransactionId } })
      : null;

    return {
      kind: 'p1_org_p2',
      p1: {
        userId: orgTxn.createdById,
        active: await userStillActive(orgTxn.createdById),
        hasEntry: !!orgTxn?.id,
      },
      p2: {
        userId: orgTxn.recipientUserId,
        active: await userStillActive(orgTxn.recipientUserId),
        hasEntry: !!personalTxn?.id,
      },
      org: {
        active: !!org,
        hasEntry: !!orgTxn?.id && !!org,
        adminIds: orgAdminIds,
      },
    };
  }

  let personalEntry = null;
  let orgEntry = null;
  let p1UserId = txn.createdById;

  if (resolvedBook.organization?.isPersonal && (txn.orgFundId || txn.clientRef)) {
    personalEntry = txn;
    if (txn.clientRef?.endsWith(CREATOR_PERSONAL_MIRROR_SUFFIX)) {
      const baseRef = txn.clientRef.slice(0, -CREATOR_PERSONAL_MIRROR_SUFFIX.length);
      orgEntry = await prisma.transaction.findFirst({ where: { clientRef: baseRef } });
    } else if (txn.linkedTransactionId) {
      orgEntry = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
    } else {
      orgEntry = await prisma.transaction.findFirst({
        where: {
          bookId: txn.orgFundId || undefined,
          clientRef: txn.clientRef || undefined,
          amount: txn.amount,
          createdById: txn.createdById,
          id: { not: txn.id },
          book: { organization: { isPersonal: false } }
        },
      });
    }
  } else if (!resolvedBook.organization?.isPersonal) {
    orgEntry = txn;
    personalEntry = await findCreatorPersonalMirror(txn);
    if (!personalEntry && txn.orgFundId) {
      personalEntry = await prisma.transaction.findFirst({
        where: { orgFundId: txn.orgFundId, amount: txn.amount, createdById: txn.createdById },
      });
    }
  }

  if (personalEntry || orgEntry) {
    const orgBookId = orgEntry?.bookId || txn.orgFundId || resolvedBook.id;
    const orgBook = orgBookId
      ? await prisma.book.findUnique({ where: { id: orgBookId }, include: { organization: true } })
      : null;
    const org = orgBook?.organizationId
      ? await prisma.organization.findUnique({ where: { id: orgBook.organizationId } })
      : null;
    const orgAdminIds = org ? await getOrgAdminUserIds(orgBook.organizationId) : [];

    return {
      kind: 'p1_org',
      p1: {
        userId: p1UserId,
        active: await userStillActive(p1UserId),
        hasEntry: !!personalEntry?.id,
      },
      org: {
        active: !!org,
        hasEntry: !!orgEntry?.id && !!org,
        adminIds: orgAdminIds,
      },
    };
  }

  // Fallback for Send to Org (personal book → org) when personalEntry wasn't set
  // (e.g. old transactions without clientRef). Any admin of the recipient org
  // can approve via orgApprovalAnyOf.
  if (txn.recipientOrgId && !txn.recipientUserId) {
    const org = await prisma.organization.findUnique({ where: { id: txn.recipientOrgId } });
    const orgAdminIds = org ? await getOrgAdminUserIds(txn.recipientOrgId) : [];
    const linked = txn.linkedTransactionId
      ? await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } })
      : null;
    return {
      kind: 'p1_org',
      p1: {
        userId: txn.createdById,
        active: await userStillActive(txn.createdById),
        hasEntry: !!txn?.id,
      },
      org: {
        active: !!org,
        hasEntry: !!linked?.id,
        adminIds: orgAdminIds,
      },
    };
  }

  const linked = txn.linkedTransactionId
    ? await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } })
    : null;
  const partyA = txn.createdById;
  const partyB = txn.recipientUserId || linked?.recipientUserId || linked?.createdById;

  if (linked || txn.recipientUserId) {
    return {
      kind: 'p1_p2',
      p1: { userId: partyA, active: await userStillActive(partyA), hasEntry: !!txn?.id },
      p2: { userId: partyB, active: await userStillActive(partyB), hasEntry: !!linked?.id },
    };
  }

  return { kind: 'solo' };
};

module.exports = {
  txnHasLinkedChangeDeleteApproval,
  linkedBookExists,
  getChangeDeleteCounterpartyUserId,
  resolveChangeDeleteChain,
  computeRequiredApprovers,
  finalizeLinkedChangeDeleteApprovers,
  buildP1OrgApprovers,
};
