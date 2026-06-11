const { prisma } = require('../config/database');
const { CREATOR_PERSONAL_MIRROR_SUFFIX } = require('../config/constants');
const { broadcastToUsers } = require('../websocket');
const { checkApprovalBypass, userStillActive, pickOrgRepresentative } = require('./access');
const { resolveOrgDisbursementOrgTxn } = require('./fund');
const { findCreatorPersonalMirror, findFundVoucherPairedTxn } = require('./mirror');
const { parsePendingData, getOrgAdminUserIds, reverseTxnBalanceForRemoval } = require('./misc');

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
    return { requiredApprovers: rep ? [rep] : chain.org.adminIds, orgApprovalAnyOf: chain.org.adminIds, chainNote: 'degraded_p1_org' };
  }
  if (requesterIsOrg) {
    return {
      requiredApprovers: chain.p1.userId ? [chain.p1.userId] : [],
      orgApprovalAnyOf: [],
      chainNote: 'degraded_p1_org',
    };
  }
  const rep = pickOrgRepresentative(chain.org.adminIds, requesterId);
  return { requiredApprovers: rep ? [rep] : chain.org.adminIds, orgApprovalAnyOf: chain.org.adminIds, chainNote: 'degraded_p1_org' };
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
      if (reqs.length === 0) reqs = [requesterId];
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
    if (reqs.length === 0) reqs = [requesterId];
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
    } else {
      orgEntry = await prisma.transaction.findFirst({
        where: {
          bookId: txn.orgFundId || undefined,
          clientRef: txn.clientRef || undefined,
          amount: txn.amount,
          createdById: txn.createdById,
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

const getCounterpartLegsForChangeDelete = async (txn, book, txClient = prisma) => {
  const legs = [];
  if (txn.linkedTransactionId) {
    const linked = await txClient.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
    if (linked) legs.push(linked);
  }
  const paired = await findFundVoucherPairedTxn(txn, book, txClient);
  if (paired && paired.id !== txn.id && !legs.some((l) => l.id === paired.id)) {
    legs.push(paired);
  }
  return legs;
};

const syncCounterpartLegsForChangeDelete = async (tx, txn, book, opts, requesterId = null) => {
  const {
    pendingAction,
    pendingData,
    fieldUpdates = {},
    historyEntry = null,
    reverseBalanceOnRequest = false,
    keepReconStatus = false
  } = opts;
  const legs = await getCounterpartLegsForChangeDelete(txn, book, tx);
  for (const leg of legs) {
    const legBook = await tx.book.findUnique({ where: { id: leg.bookId } });
    if (!legBook) continue;

    if (requesterId && legBook.organizationId) {
      const legOrg = await tx.organization.findUnique({ where: { id: legBook.organizationId }, select: { isPersonal: true } });
      if (legOrg && !legOrg.isPersonal) {
        const membership = await tx.organizationMember.findUnique({
          where: { userId_organizationId: { userId: requesterId, organizationId: legBook.organizationId } }
        });
        if (!membership || membership.status !== 'active') continue;
      }
    }

    if (reverseBalanceOnRequest) {
      const balanceAdj = leg.type === 'expense' ? leg.amount : -leg.amount;
      await tx.book.update({ where: { id: legBook.id }, data: { balance: { increment: balanceAdj } } });
    }

    const data = { ...fieldUpdates };
    if (pendingAction) {
      if (!keepReconStatus) {
        data.reconStatus = 'pending';
      }
      data.pendingAction = pendingAction;
      data.pendingData = pendingData;
    }
    if (historyEntry) {
      data.updateHistory = [...(leg.updateHistory || []), historyEntry];
    }

    await tx.transaction.update({ where: { id: leg.id }, data });
  }
};

const deleteCounterpartLegsForChangeDelete = async (tx, txn, book) => {
  const legs = await getCounterpartLegsForChangeDelete(txn, book, tx);
  for (const leg of legs) {
    let adj = reverseTxnBalanceForRemoval(leg);
    if (leg.reconStatus === 'rejected') {
      adj = 0;
    }
    if (leg.reconStatus === 'pending' && leg.type === 'income' && leg.category === 'Send') {
      adj = 0;
    }
    if (adj !== 0) {
      await tx.book.update({
        where: { id: leg.bookId },
        data: { balance: { increment: adj } }
      });
    }
    await tx.transaction.delete({ where: { id: leg.id } });
  }
};

const finalizeCounterpartLegsOnEditApprove = async (tx, txn, book, approveHistoryEntry) => {
  const legs = await getCounterpartLegsForChangeDelete(txn, book, tx);
  const source = await tx.transaction.findUnique({ where: { id: txn.id } });
  if (!source) return;

  for (const leg of legs) {
    const cur = await tx.transaction.findUnique({
      where: { id: leg.id },
      select: { version: true, updateHistory: true, amount: true, type: true, bookId: true, pendingData: true }
    });
    if (!cur) continue;

    const syncFields = {
      amount: source.amount,
      note: source.note,
      category: source.category,
      reconStatus: 'approved',
      pendingAction: null,
      pendingData: null,
      version: { increment: 1 },
      updateHistory: [...(cur.updateHistory || []), approveHistoryEntry]
    };
    await tx.transaction.updateMany({
      where: { id: leg.id, version: cur.version },
      data: syncFields
    });

    const legPd = parsePendingData(cur.pendingData);
    const legOldAmount = (legPd.oldAmount != null ? Number(legPd.oldAmount) : source.amount);
    const legDelta = cur.type === 'expense'
      ? (legOldAmount - source.amount)
      : (source.amount - legOldAmount);
    if (legDelta !== 0) {
      await tx.book.update({
        where: { id: leg.bookId },
        data: { balance: { increment: legDelta } }
      });
    }
  }
};

const buildChangeDeleteNotification = (pendingData, pendingAction, txn) => {
  const pd = parsePendingData(pendingData);
  const requester = pd.requesterName || 'Someone';
  const required = pd.requiredApprovalCount ?? (pd.requiredApprovers || []).length;
  const approved = (pd.approvals || []).length;
  const progress = required > 0 ? `${approved}/${required}` : null;

  if (pendingAction === 'delete') {
    const amount = pd.oldAmount ?? txn?.amount;
    const note = pd.oldNote ?? txn?.note ?? '';
    if (pd.isOrphan || required === 0) {
      return {
        bn: `${requester} ৳${amount} লেনদেন মুছতে চাচ্ছেন${note ? ` (“${note}”)` : ''}। বিপরীত পক্ষ/এন্ট্রি নেই — অনুমোদন লাগবে না।`,
        en: `${requester} wants to delete ৳${amount}${note ? ` ("${note}")` : ''}. Counterparty entry missing — no approval needed.`,
        shortBn: `মুছে ফেলা (অরফান): ৳${amount}${note ? ` — ${note}` : ''}`,
        shortEn: `Delete (orphan): ৳${amount}${note ? ` — ${note}` : ''}`,
        progress: null,
      };
    }
    return {
      bn: `${requester} ৳${amount} লেনদেন মুছতে চাচ্ছেন${note ? ` (“${note}”)` : ''}। ${required} জনের অনুমোদন লাগবে${progress ? ` (${progress})` : ''}।`,
      en: `${requester} wants to delete ৳${amount}${note ? ` ("${note}")` : ''}. Needs ${required} approval(s)${progress ? ` (${progress})` : ''}.`,
      shortBn: `মুছে ফেলা: ৳${amount}${note ? ` — ${note}` : ''}`,
      shortEn: `Delete: ৳${amount}${note ? ` — ${note}` : ''}`,
      progress,
    };
  }

  const oldAmount = pd.oldAmount ?? txn?.amount;
  const newAmount = pd.newAmount ?? txn?.amount;
  const oldNote = pd.oldNote ?? txn?.note ?? '';
  const newNote = pd.newNote ?? txn?.note ?? '';
  const changes = [];
  if (oldAmount != null && newAmount != null && oldAmount !== newAmount) {
    changes.push(`৳${oldAmount} → ৳${newAmount}`);
  }
  if (oldNote !== newNote) {
    changes.push(`“${oldNote || '—'}” → “${newNote || '—'}”`);
  }
  const changeText = changes.length > 0 ? changes.join(', ') : 'details updated';
  if (pd.isOrphan || required === 0) {
    return {
      bn: `${requester} লেনদেন সম্পাদন করতে চাচ্ছেন: ${changeText}। বিপরীত পক্ষ/এন্ট্রি নেই — অনুমোদন লাগবে না।`,
      en: `${requester} wants to edit: ${changeText}. Counterparty entry missing — no approval needed.`,
      shortBn: `সম্পাদনা (অরফান): ${changeText}`,
      shortEn: `Edit (orphan): ${changeText}`,
      progress: null,
      oldAmount,
      newAmount,
      oldNote,
      newNote,
    };
  }
  return {
    bn: `${requester} লেনদেন সম্পাদন করতে চাচ্ছেন: ${changeText}। ${required} জনের অনুমোদন লাগবে${progress ? ` (${progress})` : ''}।`,
    en: `${requester} wants to edit: ${changeText}. Needs ${required} approval(s)${progress ? ` (${progress})` : ''}.`,
    shortBn: `সম্পাদনা: ${changeText}`,
    shortEn: `Edit: ${changeText}`,
    progress,
    oldAmount,
    newAmount,
    oldNote,
    newNote,
  };
};

const notifyChangeDeleteApprovers = async (txn, pendingAction, pendingData) => {
  const pd = parsePendingData(pendingData);
  const approverIds = new Set([
    ...(pd.requiredApprovers || []).filter((id) => !(pd.approvals || []).includes(id)),
    ...(pd.orgApprovalAnyOf || []).filter((id) => !(pd.approvals || []).includes(id)),
  ]);
  if (approverIds.size === 0) return;
  const summary = buildChangeDeleteNotification(pendingData, pendingAction, txn);
  broadcastToUsers([...approverIds], {
    type: 'change_delete_request',
    pendingAction,
    transactionId: txn.id,
    message: summary,
  });
};

module.exports = {
  txnHasLinkedChangeDeleteApproval,
  linkedBookExists,
  getChangeDeleteCounterpartyUserId,
  resolveChangeDeleteChain,
  getLinkedPartyUserIds,
  getRequiredApproversForChangeDelete,
  mustUseChangeDeleteApprovalFlow,
  isChangeDeleteFullyApproved,
  recordChangeDeleteApproval,
  buildChangeDeletePendingData,
  getCounterpartLegsForChangeDelete,
  syncCounterpartLegsForChangeDelete,
  deleteCounterpartLegsForChangeDelete,
  finalizeCounterpartLegsOnEditApprove,
  buildChangeDeleteNotification,
  notifyChangeDeleteApprovers,
  computeRequiredApprovers,
  finalizeLinkedChangeDeleteApprovers,
  buildP1OrgApprovers,
};
