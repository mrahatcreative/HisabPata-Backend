const { broadcastToUsers } = require('../../websocket');
const { parsePendingData, createNotification } = require('../misc');

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
        bn: `${requester} ৳${amount} লেনদেন মুছতে চাচ্ছেন${note ? ` ("${note}")` : ''}। বিপরীত পক্ষ/এন্ট্রি নেই — অনুমোদন লাগবে না।`,
        en: `${requester} wants to delete ৳${amount}${note ? ` ("${note}")` : ''}. Counterparty entry missing — no approval needed.`,
        shortBn: `মুছে ফেলা (অরফান): ৳${amount}${note ? ` — ${note}` : ''}`,
        shortEn: `Delete (orphan): ৳${amount}${note ? ` — ${note}` : ''}`,
        progress: null,
      };
    }
    return {
      bn: `${requester} ৳${amount} লেনদেন মুছতে চাচ্ছেন${note ? ` ("${note}")` : ''}। ${required} জনের অনুমোদন লাগবে${progress ? ` (${progress})` : ''}।`,
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
    changes.push(`"${oldNote || '—'}" → "${newNote || '—'}"`);
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
  const notifType = pendingAction === 'edit' ? 'EDIT_REQUESTED' : 'DELETE_REQUESTED';
  const titleBn = pendingAction === 'edit' ? 'সম্পাদনার অনুরোধ' : 'মুছে ফেলার অনুরোধ';
  const msg = pendingAction === 'edit' ? summary.shortBn : summary.shortBn;
  for (const approverId of approverIds) {
    await createNotification(approverId, notifType, titleBn, msg, txn.id, txn.recipientOrgId || null);
  }
};

module.exports = {
  buildChangeDeleteNotification,
  notifyChangeDeleteApprovers,
};
