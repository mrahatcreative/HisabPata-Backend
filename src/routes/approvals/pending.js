const { prisma } = require('../../config/database');

module.exports = function(app, { authenticateToken, hasAdminOrEditorAccess, checkPermission, createNotification, getOrgAdminUserIds, resolveApprovalOrgId, parsePendingData }) {

app.get('/api/approvals/pending', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      include: { memberships: { include: { organization: { include: { books: true } } } } }
    });

    const result = [];

    // --- 1. Pending Transaction Approvals ---
    const adminOrgIds = user.memberships
      .filter(m => m.status === 'active' && (m.role === 'admin' || (m.permissions || []).includes('edit_all')))
      .map(m => m.organizationId);
    const adminBookIds = user.memberships
      .filter(m => adminOrgIds.includes(m.organizationId))
      .flatMap(m => m.organization.books.map(b => b.id));

    if (adminBookIds.length > 0) {
      const pendingTxns = await prisma.transaction.findMany({
        where: {
          reconStatus: { in: ['pending_org', 'pending_recipient', 'pending'] },
          OR: [
            {
              bookId: { in: adminBookIds },
              OR: [
                { category: 'Send' },
                { orgFundId: { not: null } },
                { recipientOrgId: { not: null } },
                { pendingAction: { not: null } }
              ]
            },
            {
              bookId: { notIn: adminBookIds },
              orgFundId: { in: adminBookIds }
            }
          ]
        },
        orderBy: { createdAt: 'desc' }
      });

      for (const txn of pendingTxns) {
        const isFundVoucher = txn.orgFundId && !adminBookIds.includes(txn.bookId);
        const book = await prisma.book.findUnique({ where: { id: txn.bookId }, include: { organization: true } });

        // Recipient-side income on personal book (linked org Send) — not an admin creation-approval item
        if (!txn.pendingAction && book?.organization?.isPersonal && txn.type === 'income' && txn.category === 'Send' && txn.linkedTransactionId) {
          const linkedSource = await prisma.transaction.findUnique({
            where: { id: txn.linkedTransactionId },
            include: { book: { include: { organization: { select: { isPersonal: true } } } } }
          });
          if (linkedSource?.type === 'expense' && linkedSource?.category === 'Send' && !linkedSource.book?.organization?.isPersonal) {
            continue;
          }
        }

        // Org/personal Send expense waiting for recipient — not an admin Approval Center item
        if (!txn.pendingAction && txn.category === 'Send' && txn.type === 'expense') {
          if (['pending_recipient', 'pending_org', 'pending'].includes(txn.reconStatus)) {
            continue;
          }
        }

        // Edit/delete requests: only show to required approvers who have not yet approved
        if (txn.pendingAction && ['edit', 'delete'].includes(txn.pendingAction)) {
          const pd = parsePendingData(txn.pendingData);
          if (pd.requestedBy === user.id) continue;
          const required = pd.requiredApprovers || [];
          const orgAnyOf = pd.orgApprovalAnyOf || [];
          if (required.length > 0 || orgAnyOf.length > 0) {
            const canSee = required.includes(user.id) || orgAnyOf.includes(user.id);
            if (!canSee) continue;
            if ((pd.approvals || []).includes(user.id)) continue;
            if (orgAnyOf.includes(user.id) && orgAnyOf.some((id) => (pd.approvals || []).includes(id))) continue;
          }
        }

        let recipientName = null;
        if (txn.recipientUserId) {
          const u = await prisma.user.findUnique({ where: { id: txn.recipientUserId }, select: { name: true } });
          recipientName = u?.name || null;
        } else if (txn.recipientOrgId) {
          const org = await prisma.organization.findUnique({ where: { id: txn.recipientOrgId }, select: { name: true } });
          recipientName = org?.name || null;
        }
        if (txn.orgFundId) {
          const orig = await prisma.transaction.findUnique({ where: { id: txn.orgFundId } });
          if (orig) {
            if (orig.recipientUserId) {
              const u = await prisma.user.findUnique({ where: { id: orig.recipientUserId }, select: { name: true } });
              recipientName = u?.name || null;
            } else if (orig.recipientOrgId) {
              const org = await prisma.organization.findUnique({ where: { id: orig.recipientOrgId }, select: { name: true } });
              recipientName = org?.name || null;
            }
          }
        }

        let bookName = book?.name || 'Unknown';
        let orgName = book?.organization?.name || 'Unknown';

        if (isFundVoucher) {
          const fundBook = await prisma.book.findUnique({ where: { id: txn.orgFundId }, include: { organization: true } });
          if (fundBook) {
            bookName = fundBook.name;
            orgName = fundBook.organization?.name || 'Unknown';
          }
        }

        const actionLabel = txn.pendingAction === 'delete'
          ? 'Delete Request'
          : txn.pendingAction === 'edit'
            ? 'Edit Approval'
            : (txn.category === 'Send' || txn.recipientOrgId) ? 'Disbursement Approval' : 'Voucher Approval';

        let senderName = null;
        const sender = await prisma.user.findUnique({ where: { id: txn.createdById }, select: { name: true } });
        senderName = sender?.name || null;

        let message = txn.note || '';
        let requesterName = null;
        let approvalProgress = null;
        let changeSummaryBn = null;
        let changeSummaryEn = null;
        let oldAmount = null;
        let newAmount = null;
        let oldNote = null;
        let newNote = null;
        let requiredApprovalCount = null;

        if (txn.pendingAction && ['edit', 'delete'].includes(txn.pendingAction)) {
          const pd = parsePendingData(txn.pendingData);
          requesterName = pd.requesterName || null;
          requiredApprovalCount = pd.requiredApprovalCount ?? (pd.requiredApprovers || []).length;
          const summary = buildChangeDeleteNotification(txn.pendingData, txn.pendingAction, txn);
          changeSummaryBn = summary.bn;
          changeSummaryEn = summary.en;
          message = summary.shortBn;
          approvalProgress = summary.progress;
          oldAmount = summary.oldAmount ?? pd.oldAmount ?? null;
          newAmount = summary.newAmount ?? txn.amount ?? null;
          oldNote = summary.oldNote ?? pd.oldNote ?? null;
          newNote = summary.newNote ?? txn.note ?? null;
        }

        result.push({
          type: (txn.category === 'Send' || txn.recipientOrgId) ? 'disbursement_approval' : 'voucher_approval',
          id: txn.id,
          refId: txn.id,
          bookId: isFundVoucher ? txn.orgFundId : txn.bookId,
          title: actionLabel,
          message,
          amount: txn.amount,
          category: txn.category,
          recipientName,
          bookName,
          orgName,
          createdAt: txn.createdAt,
          pendingAction: txn.pendingAction,
          reconStatus: txn.reconStatus,
          counterProposedAmount: txn.counterProposedAmount,
          counterProposedBy: txn.counterProposedBy,
          senderName,
          requesterName,
          approvalProgress,
          changeSummaryBn,
          changeSummaryEn,
          oldAmount,
          newAmount,
          oldNote,
          newNote,
          requiredApprovalCount,
          role: 'admin', // sender/admin view
          chainId: txn.chainId,
          chainType: txn.chainType,
          isLiability: txn.isLiability,
          adjustedAmount: txn.adjustedAmount,
        });
      }
    }

    // --- 1b. Pending Incoming Sends (user is the recipient) ---
    // Find pending income txns in user's personal books where the linked source txn's recipientUserId matches
    const personalBookIds = user.memberships
      .filter(m => m.status === 'active' && m.organization.isPersonal)
      .flatMap(m => m.organization.books.map(b => b.id));
    const incomingPendingTxns = await prisma.transaction.findMany({
      where: {
        bookId: { in: personalBookIds },
        reconStatus: { in: ['pending_recipient', 'pending'] },
        type: 'income',
        category: 'Send'
      },
      orderBy: { createdAt: 'desc' }
    });

    for (const txn of incomingPendingTxns) {
      const book = await prisma.book.findUnique({ where: { id: txn.bookId } });
      let senderName = null;
      let orgName = null;

      // Get sender and org info from the linked source transaction
      if (txn.linkedTransactionId) {
        const sourceTxn = await prisma.transaction.findUnique({
          where: { id: txn.linkedTransactionId },
          include: { book: { include: { organization: { select: { name: true } } } } }
        });
        if (sourceTxn) {
          const u = await prisma.user.findUnique({ where: { id: sourceTxn.createdById }, select: { name: true } });
          senderName = u?.name || null;
          orgName = sourceTxn.book?.organization?.name || null;
        }
      }

      result.push({
        type: 'incoming_send',
        id: txn.id,
        refId: txn.id,
        bookId: txn.bookId,
        title: 'Incoming Fund Send',
        message: txn.note || '',
        amount: txn.amount,
        category: txn.category,
        bookName: book?.name || 'Unknown',
        orgName: orgName || 'Unknown',
        senderName,
        createdAt: txn.createdAt,
        reconStatus: txn.reconStatus,
        counterProposedAmount: txn.counterProposedAmount,
        counterProposedBy: txn.counterProposedBy,
        role: 'recipient', // recipient view
        chainId: txn.chainId,
        chainType: txn.chainType,
        isLiability: txn.isLiability,
        adjustedAmount: txn.adjustedAmount,
      });
    }

    // --- 2. Pending Membership Requests (for users with manage_members permission) ---
    for (const membership of user.memberships) {
      if (membership.status === 'active' && (membership.role === 'admin' || (membership.permissions || []).includes('manage_members'))) {
        const pendingMembers = await prisma.organizationMember.findMany({
          where: { organizationId: membership.organizationId, status: 'pending' },
          include: { user: true, organization: true }
        });
        for (const pm of pendingMembers) {
          result.push({
            type: 'membership_request',
            id: pm.id,
            refId: pm.id,
            title: 'Membership Request',
            message: `${pm.user.name} wants to join ${pm.organization.name}`,
            userName: pm.user.name,
            userId: pm.userId,
            orgName: pm.organization.name,
            orgId: pm.organizationId,
            createdAt: pm.createdAt,
          });
        }
      }
    }

    // Sort by newest first
    result.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    res.json(result);
  } catch (error) {
    console.error('Fetch pending approvals error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

};
