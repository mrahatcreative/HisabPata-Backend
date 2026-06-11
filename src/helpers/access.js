const { prisma } = require('../config/database');

const hasBookAccess = async (book, userId) => {
  const membership = await prisma.organizationMember.findUnique({
    where: {
      userId_organizationId: {
        userId,
        organizationId: book.organizationId
      }
    }
  });
  return !!membership && membership.status === 'active';
};

const checkPermission = async (orgId, userId, permission) => {
  const [membership, org] = await Promise.all([
    prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId, organizationId: orgId } }
    }),
    prisma.organization.findUnique({ where: { id: orgId }, select: { isPersonal: true } })
  ]);
  if (org?.isPersonal) return true;
  if (!membership || membership.status !== 'active') return false;
  if (membership.role === 'admin') return true;
  if (membership.role === 'editor') return permission === 'edit_all';
  if (membership.role === 'viewer') return permission === 'view_books';
  const perms = membership.permissions || [];
  return perms.includes(permission);
};

const hasAdminOrEditorAccess = async (orgId, userId) => {
  return checkPermission(orgId, userId, 'edit_all');
};

const checkApprovalBypass = async (orgId, userId) => {
  const org = await prisma.organization.findUnique({
    where: { id: orgId },
    select: { isPersonal: true, approvalPolicy: true, whitelistedUserIds: true }
  });
  if (!org || org.isPersonal) return true;
  if (org.approvalPolicy === 'GLOBALLY_OFF') return true;
  if (org.approvalPolicy === 'CONDITIONAL_ON') {
    return (org.whitelistedUserIds || []).includes(userId);
  }
  return false;
};

const userStillActive = async (userId) => {
  if (!userId) return false;
  const user = await prisma.user.findUnique({ where: { id: userId }, select: { id: true } });
  return !!user;
};

const pickOrgRepresentative = (adminIds, excludeId) => adminIds.find((id) => id && id !== excludeId) || null;

module.exports = { hasBookAccess, checkPermission, hasAdminOrEditorAccess, checkApprovalBypass, userStillActive, pickOrgRepresentative };
