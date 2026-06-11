const { prisma } = require('../../config/database');
const { authenticateToken } = require('../../middleware/auth');
const { hasAdminOrEditorAccess, createNotification, getOrgAdminUserIds } = require('../../helpers');
const { DEFAULT_CATEGORIES } = require('../../config/constants');
const { broadcast } = require('../../websocket');

module.exports = function(app) {

app.post('/api/org/join', authenticateToken, async (req, res) => {
  try {
    const { inviteCode } = req.body;
    if (!inviteCode) {
      return res.status(400).json({ error: 'Invite code is required' });
    }

    const organization = await prisma.organization.findUnique({
      where: { inviteCode: inviteCode.trim().toUpperCase() }
    });

    if (!organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    if (organization.isPersonal) {
      return res.status(400).json({ error: 'Cannot join a personal organization' });
    }

    const existingMembership = await prisma.organizationMember.findUnique({
      where: {
        userId_organizationId: {
          userId: req.user.id,
          organizationId: organization.id
        }
      }
    });

    if (existingMembership) {
      if (existingMembership.status === 'pending') {
        return res.status(202).json({ message: 'Your join request is pending admin approval' });
      }
      return res.status(400).json({ error: 'You are already a member of this organization' });
    }

    const membership = await prisma.organizationMember.create({
      data: {
        userId: req.user.id,
        organizationId: organization.id,
        role: 'member',
        status: 'pending'
      }
    });

    res.json({ message: 'Join request submitted. Waiting for admin approval.', membership: { ...membership, organization } });
  } catch (error) {
    console.error('Join org error:', error);
    res.status(500).json({ error: 'Server error joining organization' });
  }
});

app.put('/api/org/:orgId/members/:memberId/role', authenticateToken, async (req, res) => {
  try {
    const { role } = req.body;
    if (!['admin', 'editor', 'member'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role. Use admin, editor, or member.' });
    }

    const callerMembership = await prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId: req.user.id, organizationId: req.params.orgId } }
    });
    if (!callerMembership || callerMembership.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins can change roles' });
    }

    const target = await prisma.organizationMember.findUnique({ where: { id: req.params.memberId } });
    if (!target) return res.status(404).json({ error: 'Member not found' });

    if (target.role === 'admin' && role !== 'admin') {
      const adminCount = await prisma.organizationMember.count({
        where: {
          organizationId: req.params.orgId,
          role: 'admin',
          status: 'active'
        }
      });
      if (adminCount <= 1) {
        return res.status(400).json({ error: 'At least one admin must remain in the organization' });
      }
    }

    const updated = await prisma.organizationMember.update({
      where: { id: req.params.memberId },
      data: { role },
      include: { user: { select: { name: true } } },
    });

    res.json({ message: `Role updated to ${role}`, member: updated });
  } catch (error) {
    console.error('Update role error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/org/:orgId/members/:memberId/permissions', authenticateToken, async (req, res) => {
  try {
    const { permissions } = req.body;
    if (!Array.isArray(permissions)) {
      return res.status(400).json({ error: 'Permissions must be an array' });
    }

    const validPermissions = ['view_books', 'add_expense', 'add_income', 'edit_all', 'manage_categories', 'manage_members', 'manage_settings'];
    for (const p of permissions) {
      if (!validPermissions.includes(p)) {
        return res.status(400).json({ error: `Invalid permission: ${p}` });
      }
    }

    const callerMembership = await prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId: req.user.id, organizationId: req.params.orgId } }
    });
    if (!callerMembership || callerMembership.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins can change permissions' });
    }

    const target = await prisma.organizationMember.findUnique({ where: { id: req.params.memberId } });
    if (!target) return res.status(404).json({ error: 'Member not found' });
    if (target.role === 'admin') {
      return res.status(400).json({ error: 'Cannot change permissions of an admin' });
    }

    const updated = await prisma.organizationMember.update({
      where: { id: req.params.memberId },
      data: { permissions },
    });

    res.json({ message: 'Permissions updated', member: updated });
  } catch (error) {
    console.error('Update permissions error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/org/:orgId/members/:memberId/action', authenticateToken, async (req, res) => {
  try {
    const { action } = req.body;
    if (!['approve', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'Action must be "approve" or "reject"' });
    }

    const callerMembership = await prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId: req.user.id, organizationId: req.params.orgId } }
    });
    if (!callerMembership || callerMembership.status !== 'active' || (callerMembership.role !== 'admin' && !(callerMembership.permissions || []).includes('manage_members'))) {
      return res.status(403).json({ error: 'Only admins or users with manage_members permission can approve/reject membership' });
    }

    const targetMembership = await prisma.organizationMember.findUnique({
      where: { id: req.params.memberId },
      include: { user: true, organization: true }
    });
    if (!targetMembership) return res.status(404).json({ error: 'Membership not found' });
    if (targetMembership.status !== 'pending') {
      return res.status(400).json({ error: 'Membership is not in pending status' });
    }

    if (action === 'approve') {
      await prisma.organizationMember.update({
        where: { id: targetMembership.id },
        data: { status: 'active' }
      });
      broadcast({ type: "data_changed" });
      return res.json({ message: 'Membership approved', member: targetMembership });
    } else {
      await prisma.organizationMember.delete({ where: { id: targetMembership.id } });
      broadcast({ type: "data_changed" });
      return res.json({ message: 'Membership rejected and removed' });
    }
  } catch (error) {
    console.error('Membership action error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/org/:orgId/members/:memberId', authenticateToken, async (req, res) => {
  try {
    const callerMembership = await prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId: req.user.id, organizationId: req.params.orgId } }
    });
    if (!callerMembership || callerMembership.status !== 'active') {
      return res.status(403).json({ error: 'Not an active member of this organization' });
    }

    const target = await prisma.organizationMember.findUnique({ where: { id: req.params.memberId } });
    if (!target) return res.status(404).json({ error: 'Member not found' });

    const isSelf = target.userId === req.user.id;

    if (!isSelf && callerMembership.role !== 'admin' && !(callerMembership.permissions || []).includes('manage_members')) {
      return res.status(403).json({ error: 'Only admins or users with manage_members permission can remove members' });
    }

    if (target.role === 'admin') {
      const adminCount = await prisma.organizationMember.count({
        where: {
          organizationId: req.params.orgId,
          role: 'admin',
          status: 'active'
        }
      });
      if (adminCount <= 1) {
        return res.status(400).json({ error: 'At least one admin must remain in the organization' });
      }
    }

    const [orgBooks, userPersonalOrg] = await Promise.all([
      prisma.book.findMany({ where: { organizationId: req.params.orgId }, select: { id: true } }),
      prisma.organization.findFirst({
        where: { isPersonal: true, members: { some: { userId: target.userId } } },
        select: { books: { where: { isDefault: true }, select: { id: true }, take: 1 } }
      })
    ]);
    const orgBookIds = orgBooks.map(b => b.id);
    const personalBookId = userPersonalOrg?.books?.[0]?.id;

    if (personalBookId && orgBookIds.length > 0) {
      const linkedPersonal = await prisma.transaction.findMany({
        where: {
          bookId: personalBookId,
          linkedTransactionId: { not: null },
          OR: [
            { createdById: target.userId },
            { recipientUserId: target.userId }
          ]
        },
        select: { id: true, linkedTransactionId: true }
      });

      const personalIds = linkedPersonal.map(t => t.id);
      const orgLinkedIds = linkedPersonal.map(t => t.linkedTransactionId).filter(Boolean);

      const allFreezeIds = [...personalIds, ...orgLinkedIds];

      const fundVouchers = await prisma.transaction.findMany({
        where: {
          bookId: { in: orgBookIds },
          createdById: target.userId,
          reconStatus: { not: 'deleted' }
        },
        select: { id: true }
      });
      allFreezeIds.push(...fundVouchers.map(t => t.id));

      if (allFreezeIds.length > 0) {
        await prisma.transaction.updateMany({
          where: { id: { in: allFreezeIds } },
          data: { reconStatus: 'FROZEN' }
        });
        await createNotification(target.userId, 'ENTRIES_FROZEN', 'এন্ট্রি হিমায়িত', `সংগঠন ছাড়ার কারণে ${allFreezeIds.length}টি এন্ট্রি হিমায়িত হয়েছে। পুনরায় জয়েন করে সক্রিয় করুন।`, null, req.params.orgId);
        const adminList = await prisma.organizationMember.findMany({
          where: { organizationId: req.params.orgId, status: 'active', role: 'admin' },
          select: { userId: true }
        });
        for (const a of adminList) {
          await createNotification(a.userId, 'MEMBER_LEFT_FROZEN', 'সদস্য সংগঠন ছেড়েছে', `${target.userId} সংগঠন ছেড়েছে। সম্পর্কিত এন্ট্রি হিমায়িত হয়েছে।`, null, req.params.orgId);
        }
      }
    }

    await prisma.organizationMember.delete({ where: { id: req.params.memberId } });
    res.json({ message: isSelf ? 'You left the organization' : 'Member removed', frozenTransactions: (linkedPersonal || []).length });
  } catch (error) {
    console.error('Remove member error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

};
