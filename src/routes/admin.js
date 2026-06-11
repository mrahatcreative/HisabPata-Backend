const { prisma } = require('../config/database');

module.exports = function(app, { authenticateToken, authenticateAdmin, upload }) {

app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: { id: true, name: true, email: true, phoneNumber: true, isAdmin: true, avatarUrl: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    });
    res.json(users);
  } catch (error) {
    console.error('[Admin] Failed to fetch users:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/ai-chats', authenticateAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const userId = req.query.userId;
    const where = userId ? { userId } : {};
    const messages = await prisma.aiChatMessage.findMany({
      where,
      include: { user: { select: { id: true, name: true, email: true, phoneNumber: true } } },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
    res.json(messages);
  } catch (error) {
    console.error('[Admin] Failed to fetch AI chats:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/complaints', authenticateAdmin, async (req, res) => {
  try {
    const complaints = await prisma.complaint.findMany({
      include: { user: { select: { id: true, name: true, email: true, phoneNumber: true } } },
      orderBy: { createdAt: 'desc' },
    });
    res.json(complaints);
  } catch (error) {
    console.error('[Admin] Failed to fetch complaints:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/admin/complaints', authenticateToken, (req, res) => {
  upload.array('files', 10)(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message });

    try {
      const { subject, message, category } = req.body;
      if (!subject || !message) {
        return res.status(400).json({ error: 'Subject and message are required' });
      }

      const imageUrls = [];
      const videoUrls = [];
      if (req.files) {
        for (const file of req.files) {
          const url = `/uploads/${file.filename}`;
          if (file.mimetype.startsWith('video/')) {
            videoUrls.push(url);
          } else {
            imageUrls.push(url);
          }
        }
      }

      const complaint = await prisma.complaint.create({
        data: { userId: req.user.id, subject, message, category: category || null, imageUrls, videoUrls },
      });
      res.status(201).json(complaint);
    } catch (error) {
      console.error('[Admin] Failed to create complaint:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
});

app.put('/api/admin/complaints/:id', authenticateAdmin, async (req, res) => {
  try {
    const { status, priority, assignedTo, response, category } = req.body;
    const data = {};
    if (status !== undefined) data.status = status;
    if (priority !== undefined) data.priority = priority;
    if (assignedTo !== undefined) data.assignedTo = assignedTo;
    if (response !== undefined) data.response = response;
    if (category !== undefined) data.category = category;

    const complaint = await prisma.complaint.update({
      where: { id: req.params.id },
      data,
      include: { user: { select: { id: true, name: true, email: true } } },
    });
    res.json(complaint);
  } catch (error) {
    console.error('[Admin] Failed to update complaint:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/orgs', authenticateAdmin, async (req, res) => {
  try {
    const orgs = await prisma.organization.findMany({
      include: {
        _count: { select: { members: true, books: true } },
        members: { where: { role: 'admin', status: 'active' }, include: { user: { select: { id: true, name: true, email: true } } } }
      },
      orderBy: { createdAt: 'desc' },
    });
    const result = orgs.map(o => ({
      id: o.id, name: o.name, isPersonal: o.isPersonal, inviteCode: o.inviteCode,
      approvalPolicy: o.approvalPolicy, createdAt: o.createdAt,
      memberCount: o._count.members, bookCount: o._count.books,
      admins: o.members.map(m => ({ id: m.user.id, name: m.user.name, email: m.user.email }))
    }));
    res.json(result);
  } catch (error) {
    console.error('[Admin] Failed to fetch orgs:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/orgs/:id/members', authenticateAdmin, async (req, res) => {
  try {
    const members = await prisma.organizationMember.findMany({
      where: { organizationId: req.params.id },
      include: { user: { select: { id: true, name: true, email: true, phoneNumber: true, isAdmin: true } } },
      orderBy: { createdAt: 'desc' },
    });
    res.json(members.map(m => ({
      id: m.id, userId: m.userId, role: m.role, status: m.status, permissions: m.permissions, createdAt: m.createdAt,
      user: m.user
    })));
  } catch (error) {
    console.error('[Admin] Failed to fetch members:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/admin/orgs/:id/members/:memberId', authenticateAdmin, async (req, res) => {
  try {
    const member = await prisma.organizationMember.findUnique({ where: { id: req.params.memberId } });
    if (!member) return res.status(404).json({ error: 'Member not found' });
    if (member.organizationId !== req.params.id) return res.status(400).json({ error: 'Member does not belong to this org' });
    await prisma.organizationMember.delete({ where: { id: req.params.memberId } });
    res.json({ message: 'Member removed' });
  } catch (error) {
    console.error('[Admin] Failed to remove member:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/admin/orgs/:id', authenticateAdmin, async (req, res) => {
  try {
    const org = await prisma.organization.findUnique({ where: { id: req.params.id } });
    if (!org) return res.status(404).json({ error: 'Organization not found' });

    const bookIds = (await prisma.book.findMany({ where: { organizationId: req.params.id }, select: { id: true } })).map(b => b.id);
    const txnIds = bookIds.length > 0
      ? (await prisma.transaction.findMany({ where: { bookId: { in: bookIds } }, select: { id: true } })).map(t => t.id)
      : [];

    await prisma.$transaction([
      prisma.transaction.updateMany({ where: { recipientOrgId: req.params.id }, data: { recipientOrgId: null } }),
      ...(bookIds.length > 0 ? [prisma.transaction.updateMany({ where: { orgFundId: { in: bookIds } }, data: { orgFundId: null } })] : []),
      ...(txnIds.length > 0 ? [prisma.transaction.updateMany({ where: { linkedTransactionId: { in: txnIds } }, data: { linkedTransactionId: null } })] : []),
      prisma.organizationMember.deleteMany({ where: { organizationId: req.params.id } }),
      ...(bookIds.length > 0 ? [prisma.transaction.deleteMany({ where: { bookId: { in: bookIds } } })] : []),
      ...(bookIds.length > 0 ? [prisma.book.deleteMany({ where: { organizationId: req.params.id } })] : []),
      prisma.organization.delete({ where: { id: req.params.id } }),
    ]);

    res.json({ message: 'Organization deleted successfully' });
  } catch (error) {
    console.error('[Admin] Failed to delete org:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.params.id } });
    if (!user) return res.status(404).json({ error: 'User not found' });

    await prisma.complaint.deleteMany({ where: { userId: req.params.id } });
    await prisma.organizationMember.deleteMany({ where: { userId: req.params.id } });

    const personalOrgs = await prisma.organization.findMany({ where: { isPersonal: true, members: { some: { userId: req.params.id } } } });
    for (const org of personalOrgs) {
      await prisma.transaction.deleteMany({ where: { book: { organizationId: org.id } } });
      await prisma.book.deleteMany({ where: { organizationId: org.id } });
      await prisma.organizationMember.deleteMany({ where: { organizationId: org.id } });
      await prisma.organization.delete({ where: { id: org.id } });
    }

    await prisma.user.delete({ where: { id: req.params.id } });
    res.json({ message: 'User deleted' });
  } catch (error) {
    console.error('[Admin] Failed to delete user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const [userCount, orgCount, bookCount, txnCount, totalExpense, totalIncome] = await Promise.all([
      prisma.user.count(),
      prisma.organization.count(),
      prisma.book.count(),
      prisma.transaction.count(),
      prisma.transaction.aggregate({ _sum: { amount: true }, where: { type: 'expense', reconStatus: 'approved' } }),
      prisma.transaction.aggregate({ _sum: { amount: true }, where: { type: 'income', reconStatus: 'approved' } }),
    ]);

    const orgTypeCounts = await prisma.organization.groupBy({
      by: ['isPersonal'],
      _count: true,
    });

    const memberCount = await prisma.organizationMember.count({ where: { status: 'active' } });
    const pendingMemberCount = await prisma.organizationMember.count({ where: { status: 'pending' } });

    res.json({
      totalUsers: userCount,
      totalOrganizations: orgCount,
      personalOrgs: orgTypeCounts.find(o => o.isPersonal)?._count || 0,
      groupOrgs: orgTypeCounts.find(o => !o.isPersonal)?._count || 0,
      totalBooks: bookCount,
      totalTransactions: txnCount,
      totalExpense: totalExpense._sum.amount || 0,
      totalIncome: totalIncome._sum.amount || 0,
      activeMembers: memberCount,
      pendingMembers: pendingMemberCount,
    });
  } catch (error) {
    console.error('[Admin] Failed to fetch stats:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/system', authenticateAdmin, async (req, res) => {
  try {
    let dbOk = false;
    try {
      await prisma.$queryRaw`SELECT 1`;
      dbOk = true;
    } catch (e) { dbOk = false; }

    const memory = process.memoryUsage();
    res.json({
      status: dbOk ? 'healthy' : 'degraded',
      nodeVersion: process.version,
      platform: process.platform,
      uptime: process.uptime(),
      memory: {
        rss: Math.round(memory.rss / 1024 / 1024),
        heapTotal: Math.round(memory.heapTotal / 1024 / 1024),
        heapUsed: Math.round(memory.heapUsed / 1024 / 1024),
      },
      database: dbOk ? 'connected' : 'disconnected',
      env: process.env.NODE_ENV || 'development',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('[Admin] Failed to fetch system status:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/admin/reset', authenticateAdmin, async (req, res) => {
  try {
    await prisma.transaction.deleteMany();
    await prisma.book.deleteMany();
    await prisma.organizationMember.deleteMany();
    await prisma.organization.deleteMany();
    await prisma.complaint.deleteMany();
    await prisma.user.deleteMany();
    res.json({ message: 'Database reset complete. Seed account will be recreated on restart.' });
  } catch (error) {
    console.error('[Admin] Failed to reset database:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

};
