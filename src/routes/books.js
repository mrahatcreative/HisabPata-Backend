const { prisma } = require('../config/database');
const { broadcast } = require('../websocket');

module.exports = function(app, { authenticateToken, recalculateBookBalance }) {
  // Get User Books (all books from all orgs user is active member of)
  app.get('/api/books', authenticateToken, async (req, res) => {
    try {
      const user = await prisma.user.findUnique({
        where: { id: req.user.id },
        include: { memberships: true }
      });

      const activeMemberships = user.memberships.filter(m => m.status === 'active');
      const pendingMemberships = user.memberships.filter(m => m.status === 'pending');

      const orgIds = activeMemberships.map(m => m.organizationId);
      const books = await prisma.book.findMany({
        where: { organizationId: { in: orgIds }, isActive: true },
        include: { organization: { select: { id: true, name: true, isPersonal: true, imageUrl: true } } }
      });

      const booksWithRole = books.map(book => {
        const membership = activeMemberships.find(m => m.organizationId === book.organizationId);
        return {
          ...book,
          role: membership?.role || 'member',
          permissions: membership?.permissions || [],
          status: 'active'
        };
      });

      // Recalculate balance from approved transactions for all active books
      await Promise.all(booksWithRole.map(async (book) => {
        const calculated = await recalculateBookBalance(book.id);
        if (calculated !== null) book.balance = calculated;
      }));

      // Include mock pending books for pending memberships so they show in the list with a pending state
      const pendingOrgIds = pendingMemberships.map(m => m.organizationId);
      const pendingOrgs = pendingOrgIds.length > 0 ? await prisma.organization.findMany({
        where: { id: { in: pendingOrgIds } },
        select: { id: true, name: true, imageUrl: true, isPersonal: true }
      }) : [];

      const pendingBooks = pendingOrgs.map(org => ({
        id: `pending_${org.id}`,
        name: org.name,
        organizationId: org.id,
        organization: { id: org.id, name: org.name, isPersonal: org.isPersonal, imageUrl: org.imageUrl },
        role: 'member',
        permissions: [],
        balance: 0.0,
        isDefault: false,
        status: 'pending'
      }));

      res.json([...booksWithRole, ...pendingBooks]);
    } catch (error) {
      console.error('Fetch books error:', error);
      res.status(500).json({ error: 'Server error fetching books' });
    }
  });

  // Create Book under an organization
  app.post('/api/books', authenticateToken, async (req, res) => {
    try {
      const { name, organizationId } = req.body;
      if (!name || !organizationId) {
        return res.status(400).json({ error: 'Name and organizationId are required' });
      }

      // Verify user is a member of the organization
      const membership = await prisma.organizationMember.findUnique({
        where: {
          userId_organizationId: {
            userId: req.user.id,
            organizationId
          }
        }
      });
      if (!membership) {
        return res.status(403).json({ error: 'Not a member of this organization' });
      }

      const book = await prisma.book.create({
        data: {
          name,
          balance: 0.0,
          organizationId,
        }
      });

      res.status(201).json(book);
    } catch (error) {
      console.error('Create book error:', error);
      res.status(500).json({ error: 'Server error creating book' });
    }
  });

  // Delete Book (default books cannot be deleted)
  app.delete('/api/books/:bookId', authenticateToken, async (req, res) => {
    try {
      if (!req.params.bookId || typeof req.params.bookId !== 'string' || req.params.bookId.length < 8) {
        return res.status(400).json({ error: 'Invalid book ID' });
      }
      const book = await prisma.book.findUnique({ where: { id: req.params.bookId } });
      if (!book) return res.status(404).json({ error: 'Book not found' });

      // Verify user is a member of the org
      const membership = await prisma.organizationMember.findUnique({
        where: {
          userId_organizationId: {
            userId: req.user.id,
            organizationId: book.organizationId
          }
        }
      });
      if (!membership || !['admin', 'editor'].includes(membership.role)) {
        return res.status(403).json({ error: 'Only admins or editors can delete books' });
      }

      // Default book cannot be deleted
      if (book.isDefault) {
        return res.status(400).json({ error: 'Default book cannot be deleted' });
      }

      // Soft delete — hide book, transactions survive
      await prisma.book.update({
        where: { id: book.id },
        data: { isActive: false },
      });

      broadcast({ type: "data_changed" });
      res.json({ message: 'Book deleted successfully' });
    } catch (error) {
      console.error('Delete book error:', error);
      res.status(500).json({ error: 'Server error deleting book' });
    }
  });
};
