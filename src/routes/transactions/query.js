const { prisma } = require('../../config/database');
const { broadcast, broadcastToUser, broadcastToUsers } = require('../../websocket');

module.exports = function(app, deps) {
  const { authenticateToken, hasBookAccess, checkPermission, hasAdminOrEditorAccess, checkApprovalBypass, createNotification, getOrgAdminUserIds, maybeMirrorOrgTxnToCreatorPersonal, getChainRemainingBalance, mustUseChangeDeleteApprovalFlow, getRequiredApproversForChangeDelete, buildChangeDeletePendingData, syncCounterpartLegsForChangeDelete, notifyChangeDeleteApprovers, buildChangeDeleteNotification, deleteCounterpartLegsForChangeDelete, reverseTxnBalanceForRemoval, generateChainId, fundSendRetryStatuses, resolveApprovalOrgId, resolveFundSendChainParts, parsePendingData, parseClientDateTime, enrichTxn, DEFAULT_CATEGORIES } = deps;

// --- CHECK TRANSACTION DELETE STATUS (counterparty existence) ---
app.get('/api/transactions/:id/delete-info', authenticateToken, async (req, res) => {
  try {
    const txnId = req.params.id;
    const txn = await prisma.transaction.findUnique({ where: { id: txnId } });
    if (!txn) return res.status(404).json({ error: 'Transaction not found' });

    const book = await prisma.book.findUnique({ where: { id: txn.bookId } });
    if (!book) return res.status(404).json({ error: 'Book not found' });

    const result = {
      hasCounterparty: false,
      counterpartyExists: false,
      counterpartyType: null,
      counterpartyName: null,
      needsApproval: false,
      requiredApproverCount: 0,
      canInstantDelete: true,
    };

    // Check linkedTransactionId (paired income/expense)
    if (txn.linkedTransactionId) {
      result.hasCounterparty = true;
      const linkedTxn = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
      if (linkedTxn) {
        const linkedBook = await prisma.book.findUnique({ where: { id: linkedTxn.bookId } });
        if (linkedBook && linkedBook.isActive) {
          result.counterpartyExists = true;
          result.counterpartyType = 'book';
          result.counterpartyName = linkedBook.name;
          // Need approval from other side
          result.needsApproval = txn.reconStatus === 'approved';
        }
      }
    }

    // Check recipientOrgId (org-to-org send)
    if (txn.recipientOrgId) {
      result.hasCounterparty = true;
      const recipientOrg = await prisma.organization.findUnique({ where: { id: txn.recipientOrgId } });
      if (recipientOrg) {
        result.counterpartyExists = true;
        result.counterpartyType = 'org';
        result.counterpartyName = recipientOrg.name;
        result.needsApproval = txn.reconStatus === 'approved';
      }
    }

    // Check orgFundId (fund transfer source)
    if (txn.orgFundId) {
      result.hasCounterparty = true;
      const fundBook = await prisma.book.findUnique({ where: { id: txn.orgFundId } });
      if (fundBook) {
        result.counterpartyExists = true;
        result.counterpartyType = 'fund';
        result.counterpartyName = fundBook.name;
        result.needsApproval = txn.reconStatus === 'approved';
      }
    }

    // Check recipientUserId (for personal recipient books)
    if (txn.recipientUserId && !txn.recipientOrgId) {
      result.hasCounterparty = true;
      const recipientUser = await prisma.user.findUnique({ where: { id: txn.recipientUserId } });
      if (recipientUser) {
        // Check if the recipient user has any active personal book
        const userPersonalBooks = await prisma.book.findMany({
          where: {
            organization: { isPersonal: true, members: { some: { userId: txn.recipientUserId } } },
            isActive: true
          },
          take: 1
        });
        if (userPersonalBooks.length > 0) {
          result.counterpartyExists = true;
          result.counterpartyType = 'user';
          result.counterpartyName = recipientUser.name;
        }
      }
    }

    if (txn.reconStatus === 'approved') {
      let mustApprove = await mustUseChangeDeleteApprovalFlow(txn, book, req.user.id);
      const requiredApprovers = await getRequiredApproversForChangeDelete(txn, book, req.user.id);
      // Orphan: counterparty no longer exists — treat as instant-delete
      if (mustApprove && requiredApprovers.length === 0) {
        mustApprove = false;
      }
      result.requiredApproverCount = mustApprove ? Math.max(1, requiredApprovers.length) : 0;
      result.needsApproval = mustApprove;
      result.canInstantDelete = !mustApprove;
    }

    return res.json(result);
  } catch (error) {
    console.error('Delete info error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get Transactions by Book (includes recipient user name)
app.get('/api/transactions/:bookId', authenticateToken, async (req, res) => {
  try {
    const { bookId } = req.params;
    const book = await prisma.book.findUnique({ where: { id: bookId } });
    if (!book) return res.status(404).json({ error: 'Book not found' });
    if (!(await hasBookAccess(book, req.user.id))) {
      return res.status(403).json({ error: 'Not authorized to view this book' });
    }

    const org = await prisma.organization.findUnique({
      where: { id: book.organizationId },
      select: { isPersonal: true }
    });

    const whereClause = { bookId };

    // Check if current user is the receiver of any Send transactions in this book
    // If so, filter out rejected transactions (receiver doesn't see rejected)
    const isPersonalOrg = org?.isPersonal === true;
    const currentUserId = req.user.id;

    const transactions = await prisma.transaction.findMany({
      where: {
        ...whereClause,
        // Filter out 'deleted' transactions for all users
        NOT: { reconStatus: 'deleted' }
      },
      orderBy: { dateTime: 'desc' }
    });

    // If this is a personal book (likely receiver's book), filter out rejected Send incomes
    // Receiver should not see rejected transactions per spec
    let filteredTransactions = transactions;
    if (isPersonalOrg) {
      filteredTransactions = transactions.filter(txn => {
        // For income Send on personal book: hide rejected
        if (txn.type === 'income' && txn.category === 'Send' && txn.reconStatus === 'rejected') {
          return false;
        }
        return true;
      });
    }

    // Enrich with recipient names and fund info using the shared helper
    const enriched = await Promise.all(filteredTransactions.map(txn => enrichTxn(txn)));

    res.json(enriched);
  } catch (error) {
    console.error('Fetch transactions error:', error);
    res.status(500).json({ error: 'Server error fetching transactions' });
  }
});
};
