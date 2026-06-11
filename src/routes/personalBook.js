const { prisma } = require('../config/database');

module.exports = function(app, { authenticateToken, hasBookAccess, enrichTxn }) {
  // ── Personal Book Helper ──
  const getPersonalBookId = async (userId) => {
    const personalOrg = await prisma.organization.findFirst({
      where: { isPersonal: true, members: { some: { userId, status: 'active' } } },
      include: { books: { where: { isDefault: true }, take: 1 } }
    });
    return personalOrg?.books?.[0]?.id || null;
  };

  // Personal Book Summary (GET /api/personal-book)
  app.get('/api/personal-book', authenticateToken, async (req, res) => {
    try {
      const bookId = await getPersonalBookId(req.user.id);
      if (!bookId) return res.status(404).json({ error: 'Personal book not found' });

      const txns = await prisma.transaction.findMany({ where: { bookId } });
      const totalIncome = txns.filter(t => t.type === 'income' && ['approved', 'FROZEN'].includes(t.reconStatus)).reduce((s, t) => s + t.amount, 0);
      const totalExpense = txns.filter(t => t.type === 'expense' && !['rejected', 'deleted'].includes(t.reconStatus)).reduce((s, t) => s + t.amount, 0);
      const balance = totalIncome - totalExpense;

      res.json({ bookId, balance, totalIncome, totalExpense, transactionCount: txns.length });
    } catch (error) {
      console.error('Personal book summary error:', error);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Personal Book Transactions (GET /api/personal-book/transactions)
  app.get('/api/personal-book/transactions', authenticateToken, async (req, res) => {
    try {
      const bookId = await getPersonalBookId(req.user.id);
      if (!bookId) return res.status(404).json({ error: 'Personal book not found' });
      req.params.bookId = bookId;
      // Forward to existing transaction listing
      const book = await prisma.book.findUnique({ where: { id: bookId } });
      if (!book) return res.status(404).json({ error: 'Book not found' });
      if (!(await hasBookAccess(book, req.user.id))) return res.status(403).json({ error: 'Not authorized' });

      const txns = await prisma.transaction.findMany({
        where: { bookId },
        orderBy: { dateTime: 'desc' },
        take: Math.min(parseInt(req.query.limit) || 100, 500),
        skip: parseInt(req.query.offset) || 0,
      });

      const enriched = await Promise.all(txns.map(t => enrichTxn(t)));
      res.json(enriched);
    } catch (error) {
      console.error('Personal book transactions error:', error);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Personal Book Income (POST /api/personal-book/income)
  app.post('/api/personal-book/income', authenticateToken, async (req, res) => {
    try {
      const bookId = await getPersonalBookId(req.user.id);
      if (!bookId) return res.status(404).json({ error: 'Personal book not found' });
      req.body.bookId = bookId;
      req.body.type = 'income';
      req.url = '/api/transactions';
      app.handle(req, res);
    } catch (error) {
      console.error('Personal book income error:', error);
      if (!res.headersSent) res.status(500).json({ error: 'Server error' });
    }
  });

  // Personal Book Expense (POST /api/personal-book/expense)
  app.post('/api/personal-book/expense', authenticateToken, async (req, res) => {
    try {
      const bookId = await getPersonalBookId(req.user.id);
      if (!bookId) return res.status(404).json({ error: 'Personal book not found' });
      req.body.bookId = bookId;
      req.body.type = 'expense';
      req.url = '/api/transactions';
      app.handle(req, res);
    } catch (error) {
      console.error('Personal book expense error:', error);
      if (!res.headersSent) res.status(500).json({ error: 'Server error' });
    }
  });

  // Personal Book Edit Transaction (PUT /api/personal-book/transactions/:id)
  app.put('/api/personal-book/transactions/:id', authenticateToken, async (req, res) => {
    try {
      const bookId = await getPersonalBookId(req.user.id);
      if (!bookId) return res.status(404).json({ error: 'Personal book not found' });

      const txn = await prisma.transaction.findUnique({ where: { id: req.params.id } });
      if (!txn) return res.status(404).json({ error: 'Transaction not found' });
      if (txn.bookId !== bookId) return res.status(403).json({ error: 'Not your personal book transaction' });

      req.url = `/api/transactions/${req.params.id}`;
      app.handle(req, res);
    } catch (error) {
      console.error('Personal book edit error:', error);
      if (!res.headersSent) res.status(500).json({ error: 'Server error' });
    }
  });

  // Personal Book Delete Transaction (DELETE /api/personal-book/transactions/:id)
  app.delete('/api/personal-book/transactions/:id', authenticateToken, async (req, res) => {
    try {
      const bookId = await getPersonalBookId(req.user.id);
      if (!bookId) return res.status(404).json({ error: 'Personal book not found' });

      const txn = await prisma.transaction.findUnique({ where: { id: req.params.id } });
      if (!txn) return res.status(404).json({ error: 'Transaction not found' });
      if (txn.bookId !== bookId) return res.status(403).json({ error: 'Not your personal book transaction' });

      req.url = `/api/transactions/${req.params.id}`;
      app.handle(req, res);
    } catch (error) {
      console.error('Personal book delete error:', error);
      if (!res.headersSent) res.status(500).json({ error: 'Server error' });
    }
  });
};
