const { prisma } = require('../../config/database');
const { authenticateToken } = require('../../middleware/auth');
const { hasAdminOrEditorAccess, createNotification, getOrgAdminUserIds } = require('../../helpers');
const { DEFAULT_CATEGORIES } = require('../../config/constants');
const { broadcast } = require('../../websocket');

module.exports = function(app) {

app.post('/api/org/create', authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) {
      return res.status(400).json({ error: 'Organization name is required' });
    }

    const inviteCode = 'HP-' + Math.random().toString(36).substring(2, 8).toUpperCase();

    const organization = await prisma.organization.create({
      data: {
        name,
        inviteCode,
        categories: DEFAULT_CATEGORIES,
      }
    });

    await prisma.organizationMember.create({
      data: {
        userId: req.user.id,
        organizationId: organization.id,
        role: 'admin',
        status: 'active'
      }
    });

    const orgBook = await prisma.book.create({
      data: {
        name: `${name} Cash Book`,
        isDefault: true,
        organizationId: organization.id,
        balance: 0.0
      }
    });

    res.status(201).json({ organization, orgBook });
  } catch (error) {
    console.error('Create org error:', error);
    res.status(500).json({ error: 'Server error creating organization' });
  }
});

app.get('/api/organizations/:orgId/approval-policy', authenticateToken, async (req, res) => {
  try {
    const { orgId } = req.params;
    const org = await prisma.organization.findUnique({
      where: { id: orgId },
      select: { approvalPolicy: true, whitelistedUserIds: true, isPersonal: true }
    });
    if (!org) return res.status(404).json({ error: 'Organization not found' });
    if (org.isPersonal) return res.status(400).json({ error: 'Personal organizations do not have approval policies' });

    if (!(await hasAdminOrEditorAccess(orgId, req.user.id))) {
      return res.status(403).json({ error: 'Only admins can view approval policy' });
    }

    res.json({ approvalPolicy: org.approvalPolicy, whitelistedUserIds: org.whitelistedUserIds });
  } catch (error) {
    console.error('Get approval policy error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/organizations/:orgId/approval-policy', authenticateToken, async (req, res) => {
  try {
    const { orgId } = req.params;
    const { approvalPolicy, whitelistedUserIds } = req.body;

    if (!['GLOBALLY_ON', 'GLOBALLY_OFF', 'CONDITIONAL_ON'].includes(approvalPolicy)) {
      return res.status(400).json({ error: 'approvalPolicy must be GLOBALLY_ON, GLOBALLY_OFF, or CONDITIONAL_ON' });
    }

    if (approvalPolicy === 'CONDITIONAL_ON' && (!Array.isArray(whitelistedUserIds) || whitelistedUserIds.length === 0)) {
      return res.status(400).json({ error: 'CONDITIONAL_ON requires at least one whitelisted user' });
    }

    const org = await prisma.organization.findUnique({
      where: { id: orgId },
      select: { isPersonal: true }
    });
    if (!org) return res.status(404).json({ error: 'Organization not found' });
    if (org.isPersonal) return res.status(400).json({ error: 'Personal organizations do not have approval policies' });

    if (!(await hasAdminOrEditorAccess(orgId, req.user.id))) {
      return res.status(403).json({ error: 'Only admins can update approval policy' });
    }

    const updated = await prisma.organization.update({
      where: { id: orgId },
      data: {
        approvalPolicy,
        whitelistedUserIds: approvalPolicy === 'CONDITIONAL_ON' ? (whitelistedUserIds || []) : []
      }
    });

    res.json({ approvalPolicy: updated.approvalPolicy, whitelistedUserIds: updated.whitelistedUserIds });
  } catch (error) {
    console.error('Update approval policy error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/org/:orgId', authenticateToken, async (req, res) => {
  try {
    const org = await prisma.organization.findUnique({
      where: { id: req.params.orgId },
      include: {
        members: { include: { user: { select: { id: true, name: true, email: true, phoneNumber: true, avatarUrl: true } } } },
        books: { select: { id: true, name: true, balance: true } },
      }
    });
    if (!org) return res.status(404).json({ error: 'Organization not found' });

    const membership = org.members.find(m => m.userId === req.user.id);
    if (!membership) return res.status(403).json({ error: 'Not a member' });

    res.json({
      organization: {
        id: org.id,
        name: org.name,
        inviteCode: org.inviteCode,
        imageUrl: org.imageUrl,
        categories: org.categories,
        approvalPolicy: org.approvalPolicy,
        whitelistedUserIds: org.whitelistedUserIds,
        createdAt: org.createdAt,
      },
      members: org.members.map(m => ({
        id: m.id,
        userId: m.userId,
        name: m.user.name,
        email: m.user.email,
        phone: m.user.phoneNumber,
        avatarUrl: m.user.avatarUrl,
        role: m.role,
        permissions: m.permissions,
        joinedAt: m.createdAt,
      })),
      books: org.books,
      callerRole: membership.role,
      callerPermissions: membership.permissions,
    });
  } catch (error) {
    console.error('Get org error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/org/:orgId/invite-code/regenerate', authenticateToken, async (req, res) => {
  try {
    const membership = await prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId: req.user.id, organizationId: req.params.orgId } }
    });
    if (!membership || membership.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins can regenerate invite code' });
    }

    const newCode = 'HP-' + Math.random().toString(36).substring(2, 8).toUpperCase();
    const updated = await prisma.organization.update({
      where: { id: req.params.orgId },
      data: { inviteCode: newCode }
    });

    res.json({ inviteCode: updated.inviteCode });
  } catch (error) {
    console.error('Regenerate invite code error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/org/:orgId/categories', authenticateToken, async (req, res) => {
  try {
    const { category } = req.body;
    if (!category || !category.trim()) {
      return res.status(400).json({ error: 'Category name is required' });
    }

    const trimmedCategory = category.trim();

    const membership = await prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId: req.user.id, organizationId: req.params.orgId } }
    });
    if (!membership || membership.status !== 'active' || (membership.role !== 'admin' && !(membership.permissions || []).includes('manage_categories') && !(membership.permissions || []).includes('manage_settings'))) {
      return res.status(403).json({ error: 'Only admins or users with manage_settings permission can manage categories' });
    }

    const org = await prisma.organization.findUnique({
      where: { id: req.params.orgId }
    });
    if (!org) return res.status(404).json({ error: 'Organization not found' });

    if (org.categories.includes(trimmedCategory)) {
      return res.status(400).json({ error: 'Category already exists' });
    }

    const updatedCategories = [...org.categories, trimmedCategory];

    const updatedOrg = await prisma.organization.update({
      where: { id: req.params.orgId },
      data: { categories: updatedCategories }
    });

    broadcast({ type: "data_changed" });
    res.json({ message: 'Category added', categories: updatedOrg.categories });
  } catch (error) {
    console.error('Add category error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/org/:orgId/categories', authenticateToken, async (req, res) => {
  try {
    const { category } = req.body;
    if (!category) return res.status(400).json({ error: 'Category name is required' });

    const membership = await prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId: req.user.id, organizationId: req.params.orgId } }
    });
    if (!membership || membership.status !== 'active' || (membership.role !== 'admin' && !(membership.permissions || []).includes('manage_categories') && !(membership.permissions || []).includes('manage_settings'))) {
      return res.status(403).json({ error: 'Only admins or users with manage_settings permission can manage categories' });
    }

    const org = await prisma.organization.findUnique({
      where: { id: req.params.orgId }
    });
    if (!org) return res.status(404).json({ error: 'Organization not found' });

    const updatedCategories = org.categories.filter(c => c !== category.trim());

    const updatedOrg = await prisma.organization.update({
      where: { id: req.params.orgId },
      data: {
        categories: updatedCategories
      }
    });

    broadcast({ type: "data_changed" });
    res.json({ message: 'Category removed successfully', categories: updatedOrg.categories });
  } catch (error) {
    console.error('Remove category error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/org/:orgId', authenticateToken, async (req, res) => {
  try {
    const { name, imageUrl } = req.body;
    const orgId = req.params.orgId;

    const org = await prisma.organization.findUnique({ where: { id: orgId } });
    if (!org) return res.status(404).json({ error: 'Organization not found' });

    const membership = await prisma.organizationMember.findUnique({
      where: {
        userId_organizationId: {
          userId: req.user.id,
          organizationId: orgId
        }
      }
    });
    if (!membership || (membership.role !== 'admin' && !(membership.permissions || []).includes('manage_settings'))) {
      return res.status(403).json({ error: 'Only admins or users with manage_settings permission can update organization settings' });
    }

    const updateData = {};
    if (name) updateData.name = name;
    if (imageUrl !== undefined) updateData.imageUrl = imageUrl;

    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    const updatedOrg = await prisma.organization.update({
      where: { id: orgId },
      data: updateData,
    });

    broadcast({ type: "data_changed" });
    res.json({ message: 'Organization updated successfully', organization: updatedOrg });
  } catch (error) {
    console.error('Update organization error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/org/:orgId', authenticateToken, async (req, res) => {
  try {
    const org = await prisma.organization.findUnique({ where: { id: req.params.orgId } });
    if (!org) return res.status(404).json({ error: 'Organization not found' });
    if (org.isPersonal) return res.status(400).json({ error: 'Cannot delete personal organization' });

    const membership = await prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId: req.user.id, organizationId: req.params.orgId } }
    });
    if (!membership || membership.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins can delete the organization' });
    }

    const orgBooks = await prisma.book.findMany({
      where: { organizationId: req.params.orgId },
      select: { id: true }
    });
    const bookIds = orgBooks.map(b => b.id);

    const deletingTxnIds = (await prisma.transaction.findMany({
      where: { bookId: { in: bookIds } },
      select: { id: true }
    })).map(t => t.id);

    await prisma.$transaction([
      prisma.transaction.updateMany({
        where: { recipientOrgId: req.params.orgId },
        data: { recipientOrgId: null }
      }),
      prisma.transaction.updateMany({
        where: { orgFundId: { in: bookIds } },
        data: { orgFundId: null }
      }),
      prisma.transaction.updateMany({
        where: { linkedTransactionId: { in: deletingTxnIds } },
        data: { linkedTransactionId: null }
      }),
      prisma.organizationMember.deleteMany({ where: { organizationId: req.params.orgId } }),
      prisma.transaction.deleteMany({ where: { bookId: { in: bookIds } } }),
      prisma.book.deleteMany({ where: { organizationId: req.params.orgId } }),
      prisma.organization.delete({ where: { id: req.params.orgId } }),
    ]);

    broadcast({ type: "data_changed" });
    res.json({ message: 'Organization deleted successfully' });
  } catch (error) {
    console.error('Delete org error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

};
