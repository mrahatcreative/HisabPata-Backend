const { prisma } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');
const { broadcast } = require('../websocket');

module.exports = function(app) {

app.get('/api/ai/tools/category-summary', authenticateToken, async (req, res) => {
  try {
    const { bookId, startDate, endDate, orgId } = req.query;
    const where = { userId: req.user.id, status: 'active' };

    const memberships = await prisma.organizationMember.findMany({ where, include: { organization: { include: { books: true } } } });

    let bookIds = [];
    if (bookId) {
      bookIds = [bookId];
    } else if (orgId) {
      const org = memberships.find(m => m.organizationId === orgId);
      if (org) bookIds = org.organization.books.map(b => b.id);
    } else {
      bookIds = memberships.flatMap(m => m.organization.books.map(b => b.id));
    }

    const dateFilter = {};
    if (startDate) dateFilter.gte = new Date(startDate);
    if (endDate) dateFilter.lte = new Date(endDate);

    const transactions = await prisma.transaction.findMany({
      where: {
        bookId: { in: bookIds },
        type: 'expense',
        reconStatus: 'approved',
        ...(Object.keys(dateFilter).length ? { dateTime: dateFilter } : {}),
      },
      select: { category: true, amount: true, dateTime: true },
    });

    const summary = {};
    let total = 0;
    for (const t of transactions) {
      const cat = t.category || 'Other';
      summary[cat] = (summary[cat] || 0) + t.amount;
      total += t.amount;
    }

    const result = Object.entries(summary)
      .map(([category, amount]) => ({
        category, amount: Math.round(amount * 100) / 100,
        percentage: total > 0 ? Math.round((amount / total) * 100) : 0,
        count: transactions.filter(t => (t.category || 'Other') === category).length,
      }))
      .sort((a, b) => b.amount - a.amount);

    res.json({ categories: result, total: Math.round(total * 100) / 100, currency: 'BDT' });
  } catch (error) {
    console.error('[AI Tools] category-summary error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/ai/tools/balance-summary', authenticateToken, async (req, res) => {
  try {
    const memberships = await prisma.organizationMember.findMany({
      where: { userId: req.user.id, status: 'active' },
      include: { organization: { include: { books: true } } },
    });

    const books = memberships.flatMap(m =>
      m.organization.books.map(b => ({
        id: b.id,
        name: b.name,
        balance: b.balance,
        organization: m.organization.name,
        isPersonal: m.organization.isPersonal,
        role: m.role,
      }))
    );

    const totalBalance = books.reduce((sum, b) => sum + b.balance, 0);
    res.json({ books, totalBalance, currency: 'BDT' });
  } catch (error) {
    console.error('[AI Tools] balance-summary error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/ai/tools/recent-transactions', authenticateToken, async (req, res) => {
  try {
    const { bookId, limit, offset, type } = req.query;
    const where = { book: { organization: { members: { some: { userId: req.user.id, status: 'active' } } } } };
    if (bookId) where.bookId = bookId;
    if (type) where.type = type;

    const transactions = await prisma.transaction.findMany({
      where,
      orderBy: { dateTime: 'desc' },
      take: Math.min(parseInt(limit || '20'), 50),
      skip: parseInt(offset || '0'),
      include: { book: { select: { name: true, organization: { select: { name: true } } } } },
    });

    const result = transactions.map(t => ({
      id: t.id, amount: t.amount, type: t.type, category: t.category,
      note: t.note, dateTime: t.dateTime, status: t.reconStatus,
      bookName: t.book.name, orgName: t.book.organization?.name,
    }));

    res.json({ transactions: result, count: result.length });
  } catch (error) {
    console.error('[AI Tools] recent-transactions error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/ai/execute', authenticateToken, async (req, res) => {
  try {
    const { action, data } = req.body;

    if (!action || !data) {
      return res.status(400).json({ error: 'Missing action or data' });
    }

    if (action === 'create_transaction') {
      const { bookId, type, amount, category, note, description, dateTime, contact, recipientUserId, recipientOrgId, orgFundId, audioNoteId } = data;
      const resolvedNote = (note || description || '').trim();

      if (!bookId || !type || !amount) {
        return res.status(400).json({ error: 'Missing required transaction fields' });
      }

      if (audioNoteId) {
        res.on('finish', async () => {
          if (res.statusCode === 200) {
            try {
              await prisma.audioNote.update({
                where: { id: audioNoteId },
                data: { status: 'completed' }
              });
            } catch (e) {
              console.error('Failed to update audio note:', e);
            }
          }
        });
      }

      const book = await prisma.book.findFirst({
        where: { id: bookId },
        include: { organization: { include: { members: { where: { userId: req.user.id } } } } }
      });

      if (!book || book.organization.members.length === 0) {
        return res.status(403).json({ error: 'Book not found or access denied' });
      }

      const parsedAmount = parseFloat(amount);
      if (!parsedAmount || parsedAmount <= 0) {
        return res.status(400).json({ error: 'Amount must be a positive number' });
      }

      let newBalance = type === 'income'
        ? book.balance + parsedAmount
        : book.balance - parsedAmount;

      const isSend = type === 'expense' && (recipientUserId || recipientOrgId);

      const txnData = {
        bookId: book.id,
        type,
        amount: parsedAmount,
        category: category || 'General',
        note: resolvedNote,
        contact: contact || null,
        recipientUserId: recipientUserId || null,
        recipientOrgId: recipientOrgId || null,
        orgFundId: orgFundId || null,
        dateTime: dateTime ? new Date(dateTime) : new Date(),
        status: isSend ? 'pending' : 'approved',
        reconStatus: isSend ? 'pending' : 'approved',
        createdById: req.user.id,
      };

      let transaction;

      if (isSend) {
        const recipientBook = await prisma.book.findFirst({
          where: { organization: { members: { some: { userId: recipientUserId, status: 'active' } } }, isDefault: true },
          include: { organization: { select: { name: true } } },
        });

        let sourceName = book.organization?.name;
        if (!sourceName && orgFundId) {
          const fundTxn = await prisma.transaction.findUnique({
            where: { id: orgFundId },
          });
          if (fundTxn?.linkedTransactionId) {
            const orgTxn = await prisma.transaction.findUnique({
              where: { id: fundTxn.linkedTransactionId },
              include: { book: { include: { organization: { select: { name: true } } } } },
            });
            sourceName = orgTxn?.book?.organization?.name;
          }
        }

        transaction = await prisma.transaction.create({ data: txnData });

        await prisma.book.update({
          where: { id: book.id },
          data: { balance: { decrement: parsedAmount } },
        });

        if (recipientBook) {
          const linkedTxn = await prisma.transaction.create({
            data: {
              bookId: recipientBook.id,
              type: 'income',
              amount: parsedAmount,
              category: category || 'Send',
              note: `Received from ${sourceName || 'Unknown'}: ${note || ''}`,
              contact: contact || null,
              orgFundId: orgFundId || null,
              linkedTransactionId: transaction.id,
              dateTime: new Date(),
              status: 'pending',
              reconStatus: 'pending',
              createdById: recipientUserId,
            },
          });
          await prisma.transaction.update({
            where: { id: transaction.id },
            data: { linkedTransactionId: linkedTxn.id },
          });
        }

        broadcast({ type: 'data_changed' });
        return res.json({
          success: true,
          message: `Send of ${parsedAmount} BDT prepared for approval in "${book.name}"`,
          transaction: { id: transaction.id, bookId, type, amount: parsedAmount, status: 'pending' },
          requiresApproval: true,
        });
      }

      const [txn, _book] = await prisma.$transaction([
        prisma.transaction.create({ data: txnData }),
        prisma.book.update({ where: { id: book.id }, data: { balance: newBalance } }),
      ]);
      transaction = txn;

      broadcast({ type: 'data_changed' });

      return res.json({
        success: true,
        message: `${type === 'income' ? 'Income' : 'Expense'} of ${parsedAmount} BDT created in "${book.name}"`,
        transaction: {
          id: transaction.id,
          bookId: transaction.bookId,
          bookName: book.name,
          type: transaction.type,
          amount: transaction.amount,
          category: transaction.category,
          note: transaction.note,
        },
        newBalance,
      });
    }

    if (action === 'create_complaint') {
      const { subject, message, category } = data;

      if (!subject || !message) {
        return res.status(400).json({ error: 'Subject and message are required' });
      }

      const complaint = await prisma.complaint.create({
        data: {
          userId: req.user.id,
          subject,
          message,
          category: category || 'Other',
        },
      });

      return res.json({
        success: true,
        message: `Complaint "${subject}" filed successfully`,
        complaint: { id: complaint.id, subject: complaint.subject },
      });
    }

    return res.status(400).json({ error: `Unknown action: ${action}` });
  } catch (error) {
    console.error('[AI Execute] Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

};
