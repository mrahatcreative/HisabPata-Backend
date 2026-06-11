const { prisma } = require('../../../config/database');
const { broadcast, broadcastToUser, broadcastToUsers } = require('../../../websocket');
const { hasBookAccess, hasAdminOrEditorAccess } = require('../../../helpers/index');
const orgSend = require('./orgSend');
const fundSend = require('./fundSend');
const disbursement = require('./disbursement');
const voucher = require('./voucher');
const normal = require('./normal');

module.exports = function(app, deps) {
  const { authenticateToken } = deps;

  app.post('/api/transactions', authenticateToken, async (req, res) => {
    try {
      const { bookId, amount, type, note, category, contact, recipientUserId, recipientOrgId, orgFundId: _orgFundId, fundBookId, fromLocation, toLocation, imageUrl, clientRef, audioNoteId } = req.body;
      const orgFundId = _orgFundId || fundBookId || null;

      if (!bookId || !amount || !type) {
        return res.status(400).json({ error: 'BookId, amount, and type are required' });
      }

      if (audioNoteId) {
        res.on('finish', async () => {
          if (res.statusCode === 201) {
            try {
              await prisma.audioNote.update({
                where: { id: audioNoteId },
                data: { status: 'completed' }
              });
            } catch (e) {
              console.error('Failed to mark audio note as completed:', e);
            }
          }
        });
      }

      const parsedAmount = parseFloat(amount);

      if (!parsedAmount || parsedAmount <= 0) {
        return res.status(400).json({ error: 'Amount must be a positive number' });
      }

      const txnClientRef = clientRef || 'cr_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
      const txnDateTime = parseClientDateTime(req.body.dateTime);
      const isSend = type === 'expense' && category === 'Send';
      const isOrgSend = isSend && !!recipientOrgId;
      const isVoucher = !!orgFundId;
      const computedFundType = type === 'expense'
        ? (orgFundId ? 'ORG' : 'PERSONAL')
        : null;

      const book = await prisma.book.findUnique({ where: { id: bookId }, include: { organization: { select: { isPersonal: true } } } });
      if (!book) {
        return res.status(404).json({ error: 'Ledger book not found' });
      }

      if (!(await hasBookAccess(book, req.user.id))) {
        return res.status(403).json({ error: 'Not authorized to use this book' });
      }

      if (!book.organization.isPersonal && !(await hasAdminOrEditorAccess(book.organizationId, req.user.id))) {
        return res.status(403).json({
          error: 'Members must record org expenses from their personal book with an org fund selected'
        });
      }

      if (!book.organization.isPersonal && type === 'expense' && category !== 'Send') {
        return res.status(400).json({
          error: 'Organization books only support Send for expenses. Use your personal book with this organization as fund for other categories.'
        });
      }

      const ctx = { book, parsedAmount, txnClientRef, txnDateTime, computedFundType, deps, req, res };

      if (isOrgSend) {
        return await orgSend(ctx);
      }

      if (isSend && book.organization.isPersonal && orgFundId && (recipientUserId || recipientOrgId)) {
        return await fundSend(ctx);
      }

      if (isSend && recipientUserId) {
        return await disbursement(ctx);
      }

      if (isVoucher) {
        return await voucher(ctx);
      }

      return await normal(ctx);
    } catch (error) {
      console.error('Create transaction error:', error);
      const hint = error?.code === 'P2022'
        ? 'Database schema out of date — run: npx prisma migrate deploy'
        : error?.code === 'P2003'
          ? 'Invalid book or linked record — try logout and sync books again'
          : null;
      res.status(500).json({
        error: hint || 'Server error creating transaction',
        ...(process.env.NODE_ENV !== 'production' && error?.message ? { detail: error.message } : {}),
      });
    }
  });
};
