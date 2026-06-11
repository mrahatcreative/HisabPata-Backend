const { prisma } = require('../../config/database');
const { broadcast, broadcastToUser, broadcastToUsers } = require('../../websocket');

module.exports = function(app, deps) {
  const { authenticateToken, hasBookAccess, checkPermission, hasAdminOrEditorAccess, checkApprovalBypass, createNotification, getOrgAdminUserIds, maybeMirrorOrgTxnToCreatorPersonal, getChainRemainingBalance, mustUseChangeDeleteApprovalFlow, getRequiredApproversForChangeDelete, buildChangeDeletePendingData, syncCounterpartLegsForChangeDelete, notifyChangeDeleteApprovers, buildChangeDeleteNotification, deleteCounterpartLegsForChangeDelete, reverseTxnBalanceForRemoval, generateChainId, fundSendRetryStatuses, resolveApprovalOrgId, resolveFundSendChainParts, parsePendingData, parseClientDateTime, enrichTxn, DEFAULT_CATEGORIES } = deps;

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

    // Org book: Send-only for expense. Other categories → personal book + org fund.
    if (!book.organization.isPersonal && type === 'expense' && category !== 'Send') {
      return res.status(400).json({
        error: 'Organization books only support Send for expenses. Use your personal book with this organization as fund for other categories.'
      });
    }

    // --- ORG-TO-ORG SEND FLOW (expense with category "Send" + recipientOrgId) ---
    if (isOrgSend) {
      const recipientBook = await prisma.book.findFirst({
        where: { organizationId: recipientOrgId, isDefault: true }
      });
      if (!recipientBook) {
        return res.status(400).json({ error: 'Recipient organization has no default book' });
      }

      // Determine bypass status for source and destination orgs
      const bypassSourceOrgApproval = await checkApprovalBypass(book.organizationId, req.user.id);
      const bypassRecipientOrgApproval = await checkApprovalBypass(recipientOrgId, req.user.id);

      const initialStatus =
        bypassSourceOrgApproval && bypassRecipientOrgApproval ? 'approved' : 'pending';

      const result = await prisma.$transaction(async (prisma) => {
        const sourceTxn = await prisma.transaction.create({
          data: {
            bookId,
            amount: parsedAmount,
            type: 'expense',
            note: note || `Transfer to organization`,
            category: 'Send',
            contact,
            recipientOrgId,
            fundType: computedFundType,
            fromLocation,
            toLocation,
            createdById: req.user.id,
            reconStatus: initialStatus,
            imageUrl,
            clientRef: txnClientRef,
            dateTime: txnDateTime
          }
        });
        const recipientTxn = await prisma.transaction.create({
          data: {
            bookId: recipientBook.id,
            amount: parsedAmount,
            type: 'income',
            note: 'Org fund transfer: ' + (note || ''),
            category: 'Send',
            contact,
            recipientOrgId: book.organizationId,
            fundType: computedFundType,
            fromLocation,
            toLocation,
            createdById: req.user.id,
            reconStatus: initialStatus,
            imageUrl,
            clientRef: txnClientRef,
            dateTime: txnDateTime
          }
        });

        // Sender balance always applied on creation (counts even in pending)
        await prisma.book.update({ where: { id: bookId }, data: { balance: { decrement: parsedAmount } } });
        if (initialStatus === 'approved') {
          await prisma.book.update({ where: { id: recipientBook.id }, data: { balance: { increment: parsedAmount } } });
        }
        await prisma.transaction.update({ where: { id: sourceTxn.id }, data: { linkedTransactionId: recipientTxn.id } });
        await prisma.transaction.update({ where: { id: recipientTxn.id }, data: { linkedTransactionId: sourceTxn.id } });
        await maybeMirrorOrgTxnToCreatorPersonal(prisma, {
          orgTxn: sourceTxn,
          orgBook: book,
          userId: req.user.id,
          txnClientRef
        });
        return sourceTxn;
      });

      broadcast({ type: "data_changed" });
      const enriched = await enrichTxn(result);

      if (initialStatus === 'pending') {
        const recipientAdmins = await prisma.organizationMember.findMany({
          where: { organizationId: recipientOrgId, status: 'active', OR: [{ role: 'admin' }, { permissions: { has: 'edit_all' } }] },
          select: { userId: true }
        });
        const adminIds = recipientAdmins.map(a => a.userId);
        broadcastToUsers(adminIds, { type: "pending_send_received", transaction: enriched });
        for (const uid of adminIds) {
          await createNotification(uid, 'SEND_RECEIVED', 'টাকা পাঠানো হয়েছে', `${req.user.name || 'কেউ'} ${parsedAmount} টাকা পাঠিয়েছে।`, enriched?.id, recipientOrgId);
        }
      }

      return res.status(201).json({ transaction: enriched, isHandshake: true, approvalBypassed: bypassSourceOrgApproval && bypassRecipientOrgApproval });
    }

    // --- PERSONAL FUNDED SEND (personal book + Send + org fund book + recipient) ---
    if (isSend && book.organization.isPersonal && orgFundId && (recipientUserId || recipientOrgId)) {
      const fundBook = await prisma.book.findUnique({
        where: { id: orgFundId },
        include: { organization: { select: { isPersonal: true, id: true } } }
      });
      const isFundOrgBook = fundBook && !fundBook.organization.isPersonal && fundBook.id !== bookId;

      if (isFundOrgBook) {
        let recipientBook = null;
        if (recipientUserId) {
          const recipientMembership = await prisma.organizationMember.findFirst({
            where: { userId: recipientUserId, organization: { isPersonal: true } },
            include: { organization: { include: { books: { where: { isDefault: true } } } } }
          });
          if (!recipientMembership || recipientMembership.organization.books.length === 0) {
            return res.status(400).json({ error: 'Recipient has no personal book' });
          }
          recipientBook = recipientMembership.organization.books[0];
        } else {
          recipientBook = await prisma.book.findFirst({
            where: { organizationId: recipientOrgId, isDefault: true }
          });
          if (!recipientBook) {
            return res.status(400).json({ error: 'Recipient organization has no default book' });
          }
        }

        const bypassFundOrgApproval = await checkApprovalBypass(fundBook.organizationId, req.user.id);
        const isSelfSend = recipientUserId === req.user.id;
        const retryStatuses = fundSendRetryStatuses(bypassFundOrgApproval, isSelfSend);
        const personalStatus = retryStatuses.personal;
        const fundOrgStatus = retryStatuses.fundOrg;
        const recipientStatus = retryStatuses.recipient;

        const chainId = generateChainId();
        const chainType = 'fund_send';

        const result = await prisma.$transaction(async (prisma) => {
          const personalTxn = await prisma.transaction.create({
            data: {
              bookId,
              amount: parsedAmount,
              type: 'expense',
              note: note || '',
              category: 'Send',
              contact,
              recipientUserId: recipientUserId || null,
              recipientOrgId: recipientOrgId || null,
              orgFundId: fundBook.id,
              fundType: computedFundType,
              fromLocation,
              toLocation,
              createdById: req.user.id,
              reconStatus: personalStatus,
              imageUrl,
              chainId,
              chainType,
              clientRef: txnClientRef,
              dateTime: txnDateTime
            }
          });

          const fundOrgTxn = await prisma.transaction.create({
            data: {
              bookId: fundBook.id,
              amount: parsedAmount,
              type: 'expense',
              note: note ? `${note} (fund send)` : 'Fund send',
              category: 'Send',
              contact,
              recipientUserId: recipientUserId || null,
              recipientOrgId: recipientOrgId || null,
              orgFundId: fundBook.id,
              fundType: computedFundType,
              fromLocation,
              toLocation,
              createdById: req.user.id,
              reconStatus: fundOrgStatus,
              imageUrl,
              chainId,
              chainType,
              clientRef: txnClientRef,
              linkedTransactionId: personalTxn.id,
              isLiability: true,
              dateTime: txnDateTime
            }
          });

          const recipientTxn = await prisma.transaction.create({
            data: {
              bookId: recipientBook.id,
              amount: parsedAmount,
              type: 'income',
              note: recipientUserId
                ? `Org fund send: ${note || ''}`
                : `Org fund transfer: ${note || ''}`,
              category: 'Send',
              contact,
              recipientUserId: recipientUserId ? req.user.id : null,
              recipientOrgId: recipientOrgId ? fundBook.organizationId : null,
              orgFundId: fundBook.id,
              fundType: computedFundType,
              fromLocation,
              toLocation,
              createdById: req.user.id,
              reconStatus: recipientStatus,
              imageUrl,
              chainId,
              chainType,
              clientRef: txnClientRef,
              dateTime: txnDateTime
            }
          });

          // Sender & fund org balance always applied on creation (counts even in pending)
          await prisma.book.update({ where: { id: bookId }, data: { balance: { decrement: parsedAmount } } });
          await prisma.book.update({ where: { id: fundBook.id }, data: { balance: { decrement: parsedAmount } } });
          if (recipientStatus === 'approved') {
            await prisma.book.update({ where: { id: recipientBook.id }, data: { balance: { increment: parsedAmount } } });
          }

          await prisma.transaction.update({
            where: { id: personalTxn.id },
            data: { linkedTransactionId: recipientTxn.id }
          });
          await prisma.transaction.update({
            where: { id: recipientTxn.id },
            data: { linkedTransactionId: personalTxn.id }
          });

          return personalTxn;
        });

        broadcast({ type: 'data_changed' });
        const enriched = await enrichTxn(result);

        if (recipientStatus === 'pending' && !isSelfSend) {
          if (recipientUserId) {
            broadcastToUser(recipientUserId, { type: 'pending_send_received', transaction: enriched });
            await createNotification(recipientUserId, 'SEND_RECEIVED', 'টাকা পাঠানো হয়েছে', `${req.user.name || 'কেউ'} ${parsedAmount} টাকা পাঠিয়েছে।`, result?.id, null);
          } else if (recipientOrgId) {
            const recipientAdmins = await prisma.organizationMember.findMany({
              where: {
                organizationId: recipientOrgId,
                status: 'active',
                OR: [{ role: 'admin' }, { permissions: { has: 'edit_all' } }]
              },
              select: { userId: true }
            });
            const adminIds = recipientAdmins.map(a => a.userId);
            broadcastToUsers(adminIds, {
              type: 'pending_send_received',
              transaction: enriched
            });
            for (const uid of adminIds) {
              await createNotification(uid, 'SEND_RECEIVED', 'টাকা পাঠানো হয়েছে', `${req.user.name || 'কেউ'} ${parsedAmount} টাকা পাঠিয়েছে।`, result?.id, recipientOrgId);
            }
          }
        }

        return res.status(201).json({
          transaction: enriched,
          isHandshake: true,
          approvalBypassed: bypassFundOrgApproval
        });
      }
    }

    // --- DISBURSEMENT FLOW (expense with category "Send" + recipientUserId) ---
    if (isSend && recipientUserId) {
      const recipientMembership = await prisma.organizationMember.findFirst({
        where: { userId: recipientUserId, organization: { isPersonal: true } },
        include: { organization: { include: { books: { where: { isDefault: true } } } } }
      });
      if (!recipientMembership || recipientMembership.organization.books.length === 0) {
        return res.status(400).json({ error: 'Recipient has no personal book' });
      }
      const recipientBook = recipientMembership.organization.books[0];

      // Determine initial state based on org approval policy
      let bypassOrgApproval = await checkApprovalBypass(book.organizationId, req.user.id);
      const isSelfSend = recipientUserId === req.user.id;
      const initialStatus = (isSelfSend && bypassOrgApproval) ? 'approved' : 'pending';

      // ── Chain / Split / Deficit logic when fund source is selected ──
      let chainId = null;
      let chainType = null;
      let fundTxnParent = null;
      if (orgFundId) {
        fundTxnParent = await prisma.transaction.findUnique({ where: { id: orgFundId } });
        if (fundTxnParent) {
          // Determine chainId — reuse or generate
          chainId = fundTxnParent.chainId;
          if (!chainId && fundTxnParent.linkedTransactionId) {
            const linkedFund = await prisma.transaction.findUnique({ where: { id: fundTxnParent.linkedTransactionId } });
            chainId = linkedFund?.chainId;
          }
          const { remaining } = await getChainRemainingBalance(orgFundId);
          if (parsedAmount > remaining) {
            return res.status(400).json({ error: `Insufficient fund balance: requested ${parsedAmount}, remaining ${remaining}` });
          }
          chainType = 'split';
        }
      }

      // Customize source note for splits
      let sourceNote = note;
      if (orgFundId && fundTxnParent) {
        const senderName = req.user.name || 'A user';
        const recipientUser = await prisma.user.findUnique({ where: { id: recipientUserId }, select: { name: true } });
        const recipientName = recipientUser?.name || 'another member';
        const transferInfo = `Transferred to ${recipientName} from ${senderName}`;
        sourceNote = note ? `${note} (${transferInfo})` : transferInfo;
      }

      const result = await prisma.$transaction(async (prisma) => {
        const sourceTxn = await prisma.transaction.create({
          data: { bookId, amount: parsedAmount, type: 'expense', note: sourceNote, category: 'Send', contact, recipientUserId, fundType: computedFundType, fromLocation, toLocation, createdById: req.user.id, reconStatus: initialStatus, imageUrl, chainId, chainType, orgFundId, clientRef: txnClientRef, dateTime: txnDateTime }
        });
        const recipientTxn = await prisma.transaction.create({
          data: { bookId: recipientBook.id, amount: parsedAmount, type: 'income', note: note || '', category: 'Send', contact, recipientUserId: req.user.id, linkedTransactionId: null, fundType: computedFundType, fromLocation, toLocation, createdById: req.user.id, reconStatus: initialStatus, chainId, chainType, dateTime: txnDateTime }
        });
        // Sender balance always applied on creation (counts even in pending)
        await prisma.book.update({ where: { id: bookId }, data: { balance: { decrement: parsedAmount } } });
        if (initialStatus === 'approved') {
          await prisma.book.update({ where: { id: recipientBook.id }, data: { balance: { increment: parsedAmount } } });
        }
        await prisma.transaction.update({ where: { id: sourceTxn.id }, data: { linkedTransactionId: recipientTxn.id } });
        await prisma.transaction.update({ where: { id: recipientTxn.id }, data: { linkedTransactionId: sourceTxn.id } });
        await maybeMirrorOrgTxnToCreatorPersonal(prisma, {
          orgTxn: sourceTxn,
          orgBook: book,
          userId: req.user.id,
          txnClientRef,
          skipMirror: isSelfSend
        });
        return sourceTxn;
      });

      broadcast({ type: "data_changed" });
      const enriched = await enrichTxn(result);

      // ── Dynamic notification to org admins ──
      const adminIds = await getOrgAdminUserIds(book.organizationId);
      const senderName = req.user.name || 'A user';
      const recipientName = enriched.recipientName || 'another member';

      if (chainType === 'split' && fundTxnParent) {
        const { remaining } = await getChainRemainingBalance(orgFundId);
        const bnMsg = `${senderName}-কে দেওয়া ${fundTxnParent.amount} টাকা থেকে ${parsedAmount} টাকা এখন ${recipientName}-এর কাছে ট্রান্সফার করা হয়েছে। ${senderName}-এর অবশিষ্টাংশ: ${remaining} টাকা।`;
        const enMsg = `${parsedAmount} Tk from the ${fundTxnParent.amount} Tk given to ${senderName} has been transferred to ${recipientName}. ${senderName}'s remaining: ${remaining} Tk.`;
        broadcastToUsers(adminIds, { type: "chain_split", message: { bn: bnMsg, en: enMsg }, transaction: enriched });
      } else if (chainType === 'deficit') {
        const deficitAmt = parsedAmount;
        const bnMsg = `${senderName} ${enriched.fundName || 'ফান্ড'} থেকে ${recipientName}-কে ${deficitAmt} টাকা অগ্রিম (Advance) পাঠিয়েছে। ${senderName}-এর বর্তমান ফান্ড ব্যালেন্স: -${deficitAmt} টাকা।`;
        const enMsg = `${senderName} sent ${deficitAmt} Tk as an advance from ${enriched.fundName || 'the fund'} to ${recipientName}. ${senderName}'s current fund balance: -${deficitAmt} Tk.`;
        broadcastToUsers(adminIds, { type: "deficit_send", message: { bn: bnMsg, en: enMsg }, transaction: enriched });
      }

      // Notify recipient
      if (initialStatus !== 'approved') {
        broadcastToUser(recipientUserId, { type: "pending_send_received", transaction: enriched });
        await createNotification(recipientUserId, 'SEND_RECEIVED', 'টাকা পাঠানো হয়েছে', `${req.user.name || 'কেউ'} ${parsedAmount} টাকা পাঠিয়েছে।`, result?.id, null);
      }
      return res.status(201).json({ transaction: enriched, isHandshake: true, approvalBypassed: bypassOrgApproval });
    }

    // --- VOUCHER FLOW ---
    if (isVoucher) {
      let isVoucherTxn = false;
      let isVoucherBook = false;
      let targetBook = null;
      let origDisbursement = null;

      origDisbursement = await prisma.transaction.findUnique({ where: { id: orgFundId } });
      if (origDisbursement) {
        isVoucherTxn = true;
      } else {
        targetBook = await prisma.book.findUnique({ where: { id: orgFundId } });
        if (targetBook) {
          isVoucherBook = true;
        } else {
          return res.status(404).json({ error: 'Original disbursement or target book not found' });
        }
      }

      const voucherOrgBook = isVoucherTxn
        ? await prisma.book.findUnique({ where: { id: origDisbursement.bookId } })
        : targetBook;
      if (!voucherOrgBook) {
        return res.status(400).json({ error: 'Target organization book not found' });
      }

      if (voucherOrgBook.organizationId) {
        const voucherOrgMember = await prisma.organizationMember.findFirst({
          where: { userId: req.user.id, organizationId: voucherOrgBook.organizationId, status: 'active' }
        });
        if (!voucherOrgMember) {
          return res.status(403).json({ error: 'Not a member of the target organization' });
        }
      }

      // Create the transaction in the ORGANIZATION's book (not creator's personal book)
      // as pending_org — org admin must approve before balance takes effect
      const txn = await prisma.transaction.create({
        data: {
          bookId: voucherOrgBook.id,
          amount: parsedAmount,
          type: 'expense',
          note,
          category,
          contact,
          orgFundId: isVoucherTxn ? origDisbursement.bookId : targetBook.id,
          fundType: computedFundType,
          fromLocation,
          toLocation,
          createdById: req.user.id,
          reconStatus: 'pending_org',
          imageUrl,
          clientRef: txnClientRef,
          dateTime: txnDateTime
        }
      });

      // Mirror to creator's personal book so they can track it
      await maybeMirrorOrgTxnToCreatorPersonal(prisma, {
        orgTxn: txn,
        orgBook: voucherOrgBook,
        userId: req.user.id,
        txnClientRef
      });

      // Notify org admins about pending voucher
      const orgAdmins = await prisma.organizationMember.findMany({
        where: { organizationId: voucherOrgBook.organizationId, status: 'active', OR: [{ role: 'admin' }, { permissions: { has: 'edit_all' } }] },
        select: { userId: true }
      });
      const adminIds = orgAdmins.map(a => a.userId);
      broadcastToUsers(adminIds, { type: 'pending_voucher', transaction: txn });
      for (const uid of adminIds) {
        await createNotification(uid, 'VOUCHER_PENDING', 'নতুন খরচ অনুমোদন প্রয়োজন', `${req.user.name || 'কেউ'} ${parsedAmount} টাকার একটি খরচ এন্ট্রি জমা দিয়েছে।`, txn.id, voucherOrgBook.organizationId);
      }

      broadcast({ type: "data_changed" });
      const enriched = await enrichTxn(txn);
      return res.status(201).json({ transaction: enriched, book: await prisma.book.findUnique({ where: { id: voucherOrgBook.id } }), isVoucher: true });
    }

    // --- NORMAL INCOME/EXPENSE ---
    const balanceOp = type === 'income' ? { increment: parsedAmount } : { decrement: parsedAmount };

    // Determine if this is a general expense needing org approval
    let initialStatus = 'approved';
    if (type === 'expense' && !book.organization.isPersonal) {
      const bypass = await checkApprovalBypass(book.organizationId, req.user.id);
      initialStatus = bypass ? 'approved' : 'pending_org';
    }



    const createResult = await prisma.$transaction(async (tx) => {
      const transaction = await tx.transaction.create({
        data: { bookId, amount: parsedAmount, type, note, category, contact, fundType: computedFundType, fromLocation, toLocation, createdById: req.user.id, reconStatus: initialStatus, imageUrl, clientRef: txnClientRef, dateTime: txnDateTime }
      });
      await tx.book.update({ where: { id: bookId }, data: { balance: balanceOp } });
      await maybeMirrorOrgTxnToCreatorPersonal(tx, {
        orgTxn: transaction,
        orgBook: book,
        userId: req.user.id,
        txnClientRef
      });
      const updatedBook = await tx.book.findUnique({ where: { id: bookId } });
      return { transaction, updatedBook };
    });

    broadcast({ type: "data_changed" });
    const enriched = await enrichTxn(createResult.transaction);
    res.status(201).json({ transaction: enriched, book: createResult.updatedBook });
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
