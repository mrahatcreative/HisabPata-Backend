const { prisma } = require('../../config/database');
const { broadcast, broadcastToUser, broadcastToUsers } = require('../../websocket');

module.exports = function(app, deps) {
  const { authenticateToken, hasBookAccess, checkPermission, hasAdminOrEditorAccess, checkApprovalBypass, createNotification, getOrgAdminUserIds, maybeMirrorOrgTxnToCreatorPersonal, getChainRemainingBalance, mustUseChangeDeleteApprovalFlow, getRequiredApproversForChangeDelete, buildChangeDeletePendingData, syncCounterpartLegsForChangeDelete, notifyChangeDeleteApprovers, buildChangeDeleteNotification, deleteCounterpartLegsForChangeDelete, reverseTxnBalanceForRemoval, generateChainId, fundSendRetryStatuses, resolveApprovalOrgId, resolveFundSendChainParts, parsePendingData, parseClientDateTime, enrichTxn, DEFAULT_CATEGORIES, handleOrgFundTransition } = deps;

// --- EDIT TRANSACTION ---
app.put('/api/transactions/:id', authenticateToken, async (req, res) => {
  console.log(`[DEBUG] 1. Entering edit route for txnId: ${req.params.id}`);
  try {
    const { amount, type, note, category, contact, recipientUserId, recipientOrgId, imageUrl, orgFundId, fromLocation, toLocation, dateTime: clientDateTime } = req.body;
    const txnId = req.params.id;

    const txn = await prisma.transaction.findUnique({ where: { id: txnId } });
    if (!txn) return res.status(404).json({ error: { bn: 'লেনদেন পাওয়া যায়নি।', en: 'Transaction not found' } });

    if (txn.reconStatus === 'FROZEN') {
      return res.status(422).json({ error: { bn: 'ফ্রোজেন লেনদেন সম্পাদনা করা যাবে না। পুনরায় সংগঠনে যোগ দিন।', en: 'Frozen transaction cannot be edited. Rejoin the organization to modify this entry.' } });
    }

    const book = await prisma.book.findUnique({ where: { id: txn.bookId }, include: { organization: { select: { isPersonal: true } } } });
    if (!book) return res.status(404).json({ error: { bn: 'বই পাওয়া যায়নি।', en: 'Book not found' } });

    // ── Authorization: Who can edit? ──
    // Sender (createdById) can always edit their own Send transactions.
    // Receiver can NOT edit pending transactions.
    // Org admins/editors retain full access.
    const isSender = txn.createdById === req.user.id;
    const isReceiver = txn.recipientUserId === req.user.id;
    const isSend = txn.category === 'Send';
    const isPending = txn.reconStatus === 'pending';
    const isApproved = txn.reconStatus === 'approved';
    const isRejected = txn.reconStatus === 'rejected';
    const isAdminOrEditor = await hasAdminOrEditorAccess(book.organizationId, req.user.id);

    if (isSend) {
      // ── Block recipient & type change on any Send, regardless of state ──
      if (type !== undefined && type !== txn.type) {
        return res.status(400).json({ error: { bn: 'Send লেনদেনের ধরণ (type) পরিবর্তন করা যাবে না।', en: 'Cannot change transaction type on a Send transaction.' } });
      }
      if (recipientUserId !== undefined && recipientUserId !== txn.recipientUserId) {
        return res.status(400).json({ error: { bn: 'Send লেনদেনের প্রাপক পরিবর্তন করা যাবে না।', en: 'Cannot change recipient on a Send transaction.' } });
      }
      if (recipientOrgId !== undefined && recipientOrgId !== txn.recipientOrgId) {
        return res.status(400).json({ error: { bn: 'Send লেনদেনের প্রাপক প্রতিষ্ঠান পরিবর্তন করা যাবে না।', en: 'Cannot change recipient organization on a Send transaction.' } });
      }

      // Send transaction rules
      if (isPending) {
        // Receiver cannot edit pending transactions
        if (isReceiver) {
          return res.status(403).json({ error: { bn: 'প্রাপক অপেক্ষমাণ লেনদেন সম্পাদনা করতে পারবেন না।', en: 'Receiver cannot edit a pending transaction' } });
        }
        // Only sender or admin/editor can edit
        if (!isSender && !isAdminOrEditor) {
          return res.status(403).json({ error: { bn: 'শুধু প্রেরক, অ্যাডমিন বা এডিটর এই লেনদেন সম্পাদনা করতে পারেন।', en: 'Only the sender, admins, or editors can edit this transaction' } });
        }
      } else if (isRejected) {
        // Only sender or admin/editor can edit rejected
        if (!isSender && !isAdminOrEditor) {
          return res.status(403).json({ error: { bn: 'শুধু প্রেরক, অ্যাডমিন বা এডিটর প্রত্যাখ্যাত লেনদেন সম্পাদনা করতে পারেন।', en: 'Only the sender, admins, or editors can edit a rejected transaction' } });
        }
      } else if (isApproved) {
        // Both parties can initiate edit on approved transactions
        if (!isSender && !isReceiver && !isAdminOrEditor) {
          return res.status(403).json({ error: { bn: 'এই লেনদেন সম্পাদনার অনুমতি নেই।', en: 'Not authorized to edit this transaction' } });
        }
      } else {
        // Fallback: admin/editor only
        if (!isAdminOrEditor) {
          return res.status(403).json({ error: { bn: 'শুধু অ্যাডমিন বা এডিটর লেনদেন সম্পাদনা করতে পারেন।', en: 'Only admins or editors can edit transactions' } });
        }
      }
    } else {
      // Non-Send transactions: existing rule
      if (!isAdminOrEditor) {
        return res.status(403).json({ error: { bn: 'শুধু অ্যাডমিন বা এডিটর লেনদেন সম্পাদনা করতে পারেন।', en: 'Only admins or editors can edit transactions' } });
      }
    }

    // If personal book txn has linked org txn, check if user is still a member of that org
    if (book.organization.isPersonal && txn.linkedTransactionId) {
      const linkedTxn = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { bookId: true } });
      if (linkedTxn) {
        const linkedBook = await prisma.book.findUnique({ where: { id: linkedTxn.bookId }, select: { organizationId: true } });
        if (linkedBook) {
          const linkedOrg = await prisma.organization.findUnique({ where: { id: linkedBook.organizationId }, select: { isPersonal: true } });
          if (linkedOrg && !linkedOrg.isPersonal) {
            const membership = await prisma.organizationMember.findUnique({
              where: { userId_organizationId: { userId: req.user.id, organizationId: linkedBook.organizationId } }
            });
            if (!membership || membership.status !== 'active') {
              return res.status(403).json({ error: { bn: 'সংগঠন থেকে leave করার পর এই entry edit করা যাবে না। আবার জয়েন করুন।', en: 'Cannot edit this entry after leaving the organization. Rejoin to modify.' } });
            }
          }
        }
      }
    }

    const finalType = type !== undefined ? type : txn.type;
    const finalCategory = category !== undefined ? category : txn.category;
    const isExistingOrgFundMirror =
      !book.organization.isPersonal &&
      txn.type === 'expense' &&
      txn.category &&
      txn.category !== 'Send';
    if (
      !book.organization.isPersonal &&
      finalType === 'expense' &&
      finalCategory !== 'Send' &&
      !isExistingOrgFundMirror
    ) {
      return res.status(400).json({
        error: { bn: 'সংগঠনের বই শুধু Send ব্যয়ের জন্য। অন্য ক্যাটাগরির জন্য আপনার ব্যক্তিগত বই ব্যবহার করুন এই সংগঠনকে ফান্ড হিসেবে।', en: 'Organization books only support Send for expenses. Use your personal book with this organization as fund for other categories.' }
      });
    }
    if (isExistingOrgFundMirror && category !== undefined && category === 'Send') {
      return res.status(400).json({
        error: { bn: 'ফান্ড ভাউচার এন্ট্রি Send-এ পরিবর্তন করা যাবে না। শুধু পরিমাণ বা নোট সম্পাদনা করুন।', en: 'Fund voucher entries cannot be changed to Send. Edit amount or note only.' }
      });
    }

    const changes = {};
    if (amount !== undefined) {
      const parsed = parseFloat(amount);
      if (!Number.isFinite(parsed) || parsed <= 0) return res.status(400).json({ error: { bn: 'পরিমাণ একটি সঠিক ধনাত্মক সংখ্যা হতে হবে।', en: 'Amount must be a valid positive number' } });
      changes.amount = parsed;
    }
    if (type !== undefined) changes.type = type;
    if (note !== undefined) changes.note = note;
    if (category !== undefined) changes.category = category;
    if (contact !== undefined) changes.contact = contact;
    if (recipientUserId !== undefined) changes.recipientUserId = recipientUserId;
    if (recipientOrgId !== undefined) changes.recipientOrgId = recipientOrgId;
    if (imageUrl !== undefined) changes.imageUrl = imageUrl;
    if (fromLocation !== undefined) changes.fromLocation = fromLocation;
    if (toLocation !== undefined) changes.toLocation = toLocation;
    if (orgFundId !== undefined) {
      if (orgFundId === null || orgFundId === '') {
        changes.orgFundId = null;
        changes.fundType = 'PERSONAL';
      } else {
        const fundBook = await prisma.book.findUnique({ where: { id: orgFundId } });
        if (!fundBook) return res.status(400).json({ error: { bn: 'অবৈধ তহবিল উৎস।', en: 'Invalid fund source' } });
        changes.orgFundId = orgFundId;
        changes.fundType = 'ORG';
      }
    }
    if (clientDateTime !== undefined && clientDateTime !== null && clientDateTime !== '') {
      changes.dateTime = parseClientDateTime(clientDateTime);
    }

    if (Object.keys(changes).length === 0) return res.status(400).json({ error: { bn: 'কোনো ফিল্ড আপডেট করা হয়নি।', en: 'No fields to update' } });

    if (changes.amount !== undefined && (!changes.amount || changes.amount <= 0)) {
      return res.status(400).json({ error: { bn: 'পরিমাণ একটি ধনাত্মক সংখ্যা হতে হবে।', en: 'Amount must be a positive number' } });
    }

    const parsedAmount = changes.amount !== undefined ? changes.amount : txn.amount;
    const parsedType = changes.type !== undefined ? changes.type : txn.type;

    if (txn.pendingAction) {
      return res.status(400).json({ error: { bn: 'লেনদেনটি ইতিমধ্যে সম্পাদনা বা মুছে ফেলার জন্য অনুমোদনের অপেক্ষায় আছে।', en: 'Transaction is already pending an approval for edit or delete.' } });
    }

    const user = await prisma.user.findUnique({ where: { id: req.user.id }, select: { name: true } });

    // ── Detect org fund transition: personal → org fund ──
    const isAddingOrgFund =
      !txn.pendingAction &&
      !isSend &&
      book.organization.isPersonal &&
      !txn.orgFundId &&
      changes.orgFundId;

    if (isAddingOrgFund) {
      return await handleOrgFundTransition(req, res, deps, {
        txn, book, user, changes,
        parsedAmount,
        parsedType: finalType,
      });
    }

    // ── Block removing orgFundId from rejected org_fund transition txn ──
    if (
      isRejected &&
      txn.orgFundId &&
      book.organization.isPersonal &&
      changes.orgFundId === null
    ) {
      return res.status(400).json({ error: { bn: 'প্রত্যাখ্যাত ট্রানজিশন এন্ট্রি থেকে তহবিল সংযোগ সরানো যাবে না।', en: 'Cannot remove org fund association from a rejected transition entry.' } });
    }

    // ── Send transaction edit logic based on state ──
    let mustApprove = false;
    let isEditOnRejected = false;

    if (isSend) {
      if (isPending) {
        // Pending Send: direct edit, no balance change needed
        mustApprove = false;
      } else if (isRejected) {
        // Rejected Send: reset to pending with new values
        mustApprove = false;
        isEditOnRejected = true;
      } else if (isApproved) {
        // Approved Send: pending edit, other party must approve
        mustApprove = true;
      } else {
        mustApprove = await mustUseChangeDeleteApprovalFlow(txn, book, req.user.id);
      }
    } else {
      // Personal org fund rejected txns: skip approval, direct edit only
      const isRejectedOrgFund = isRejected && book.organization.isPersonal && txn.orgFundId;
      if (isRejectedOrgFund) {
        mustApprove = false;
      } else {
        mustApprove = await mustUseChangeDeleteApprovalFlow(txn, book, req.user.id);
      }
    }

    const requiredApprovers = await getRequiredApproversForChangeDelete(txn, book, req.user.id);
    if (mustApprove && requiredApprovers.length === 0) {
      mustApprove = false;
    }

    if (!mustApprove) {
      // Direct edit logic
      let balanceAdjustment = 0;
      const isPendingOrRejectedSend = isSend && (isPending || isRejected);

      // Balance counts in pending — adjust for amount changes or re-apply on retry
      if (isPendingOrRejectedSend) {
        if (changes.amount !== undefined && changes.amount !== txn.amount) {
          // Both Pending and Rejected: balance was already applied and never reversed.
          // Reverse the old effect and apply the new effect (accounting for possible type change).
          const reverseOld = txn.type === 'expense' ? txn.amount : -txn.amount;
          const applyNew = parsedType === 'expense' ? -parsedAmount : parsedAmount;
          balanceAdjustment = reverseOld + applyNew;
        }
      } else {
        if (isRejected && book.organization.isPersonal && txn.orgFundId) {
          // Org fund transition rejected: balance was NEVER reversed on personal book.
          // Only adjust for amount/type changes (differential).
          if (changes.amount !== undefined && changes.amount !== txn.amount) {
            const reverseOld = txn.type === 'expense' ? txn.amount : -txn.amount;
            const applyNew = parsedType === 'expense' ? -parsedAmount : parsedAmount;
            balanceAdjustment = reverseOld + applyNew;
          }
        } else if (isRejected) {
          // If a non-Send transaction was rejected, its balance was FULLY reversed.
          // Retrying it means we must apply the new amount in full (accounting for possible type change).
          if (parsedType === 'expense') balanceAdjustment = -parsedAmount;
          else if (parsedType === 'income') balanceAdjustment = parsedAmount;
        } else if (
          changes.amount !== undefined &&
          changes.amount !== txn.amount
        ) {
          // Reverse the old effect and apply the new effect (accounting for possible type change).
          const reverseOld = txn.type === 'expense' ? txn.amount : -txn.amount;
          const applyNew = parsedType === 'expense' ? -parsedAmount : parsedAmount;
          balanceAdjustment = reverseOld + applyNew;
        }
      }

      let updated;
      try {
        updated = await prisma.$transaction(async (prisma) => {
          const updateData = {
            ...changes,
            updateHistory: [
              ...(txn.updateHistory || []),
              {
                timestamp: new Date().toISOString(),
                userId: req.user.id,
                userName: user?.name || 'Unknown',
                action: isEditOnRejected ? 'edit_and_retry' : 'edit',
                changes: { old: { amount: txn.amount, type: txn.type, category: txn.category, note: txn.note }, new: changes },
              },
            ],
          };

          // If editing a rejected Send, reset to pending
          if (isEditOnRejected) {
            updateData.reconStatus = 'pending';
            updateData.pendingAction = null;
            updateData.pendingData = null;
          }

          const updatedTxn = await prisma.transaction.update({
            where: { id: txnId },
            data: updateData,
          });

          if (balanceAdjustment !== 0) {
            const updatedBook = await prisma.book.updateMany({
              where: { id: book.id, balance: book.balance },
              data: { balance: { increment: balanceAdjustment } }
            });
            if (updatedBook.count === 0) {
              throw new Error('Concurrency conflict on book balance update');
            }
          }

          const linkedChanges = {};
          if (changes.amount !== undefined) linkedChanges.amount = parsedAmount;
          if (changes.note !== undefined) linkedChanges.note = changes.note;
          if (changes.category !== undefined) linkedChanges.category = changes.category;

          // RECREATE DELETED RECEIVER LEG ON RETRY
          if (isEditOnRejected && isSend) {
            let recipientBook = null;
            if (txn.recipientUserId) {
              const recipientMembership = await prisma.organizationMember.findFirst({
                where: { userId: txn.recipientUserId, organization: { isPersonal: true } },
                include: { organization: { include: { books: { where: { isDefault: true } } } } }
              });
              if (recipientMembership && recipientMembership.organization.books.length > 0) {
                recipientBook = recipientMembership.organization.books[0];
              }
            } else if (txn.recipientOrgId) {
              recipientBook = await prisma.book.findFirst({
                where: { organizationId: txn.recipientOrgId, isDefault: true }
              });
            }
            
            if (recipientBook) {
              const recipientTxn = await prisma.transaction.create({
                data: {
                  bookId: recipientBook.id,
                  amount: parsedAmount,
                  type: txn.type === 'expense' ? 'income' : 'expense',
                  note: changes.note !== undefined ? changes.note : txn.note,
                  category: 'Send',
                  contact: txn.contact,
                  recipientUserId: txn.recipientUserId ? req.user.id : null,
                  recipientOrgId: txn.recipientOrgId ? book.organizationId : null,
                  orgFundId: txn.orgFundId,
                  fundType: txn.fundType,
                  fromLocation: txn.fromLocation,
                  toLocation: txn.toLocation,
                  createdById: req.user.id,
                  reconStatus: 'pending',
                  imageUrl: txn.imageUrl,
                  chainId: txn.chainId,
                  chainType: txn.chainType,
                  clientRef: txn.clientRef,
                  linkedTransactionId: updatedTxn.id,
                  dateTime: txn.dateTime
                }
              });
              
              await prisma.transaction.update({
                where: { id: updatedTxn.id },
                data: { linkedTransactionId: recipientTxn.id }
              });
              
              const balanceAdjustment = recipientTxn.type === 'income' ? parsedAmount : -parsedAmount;
              await prisma.book.update({
                where: { id: recipientBook.id },
                data: { balance: { increment: balanceAdjustment } }
              });
            }
          }

          if (Object.keys(linkedChanges).length > 0) {
            const counterpartUpdateData = { ...linkedChanges };
            if (isEditOnRejected) {
              counterpartUpdateData.reconStatus = 'pending';
              counterpartUpdateData.pendingAction = null;
              counterpartUpdateData.pendingData = null;
            }
            await syncCounterpartLegsForChangeDelete(prisma, txn, book, {
              fieldUpdates: counterpartUpdateData,
              historyEntry: {
                timestamp: new Date().toISOString(),
                userId: req.user.id,
                userName: user?.name || 'Unknown',
                action: isEditOnRejected ? 'edit_and_retry (counterpart)' : 'edit (counterpart)',
                changes: { new: linkedChanges }
              }
            }, req.user.id);
          }

          return updatedTxn;
        });
      } catch (err) {
        console.error('Error during direct edit transaction sync:', err);
        return res.status(500).json({ error: 'Failed to process direct edit. Internal error.' });
      }

      broadcast({ type: 'data_changed' });
      const enriched = await enrichTxn(updated);
      const recipientId = txn.recipientUserId || updated.recipientUserId;
      if (recipientId && recipientId !== req.user.id) {
        if (isEditOnRejected && isSend) {
          await createNotification(recipientId, 'SEND_RECEIVED', 'টাকা পাঠানো হয়েছে', `${user?.name || 'কেউ'} পুনরায় ${parsedAmount} টাকা পাঠিয়েছে।`, updated.linkedTransactionId || txnId, book.organizationId);
          broadcastToUser(recipientId, { type: 'pending_send_received' });
        } else {
          await createNotification(recipientId, 'EDIT_COMPLETED', 'লেনদেন সম্পাদিত', `${user?.name || 'কেউ'} লেনদেনটি সম্পাদনা করেছেন।`, txnId, book.organizationId);
        }
      }
      return res.json({ transaction: enriched, message: isEditOnRejected ? 'Transaction retried with edits' : 'Transaction updated' });
    } else {
      // Pending edit request flow — balance must be read inside transaction
      console.log(`[DEBUG] 4. Before buildChangeDeletePendingData()`);
      const pendingData = await buildChangeDeletePendingData(txn, book, req.user.id, {
        oldAmount: txn.amount,
        oldType: txn.type,
        oldCategory: txn.category,
        oldNote: txn.note,
        oldRecipientUserId: txn.recipientUserId,
        oldLinkedTransactionId: txn.linkedTransactionId,
        oldOrgFundId: txn.orgFundId,
        oldTransactionTime: txn.dateTime,
        oldContact: txn.contact,
        oldImageUrl: txn.imageUrl,
        oldFromLocation: txn.fromLocation,
        oldToLocation: txn.toLocation,
        newAmount: changes.amount !== undefined ? parsedAmount : txn.amount,
        newNote: changes.note !== undefined ? changes.note : txn.note,
        newCategory: changes.category !== undefined ? changes.category : txn.category,
        newTransactionTime: changes.dateTime !== undefined ? changes.dateTime : txn.dateTime,
        newContact: changes.contact !== undefined ? changes.contact : txn.contact,
        newImageUrl: changes.imageUrl !== undefined ? changes.imageUrl : txn.imageUrl,
        newFromLocation: changes.fromLocation !== undefined ? changes.fromLocation : txn.fromLocation,
        newToLocation: changes.toLocation !== undefined ? changes.toLocation : txn.toLocation,
      });
      console.log(`[DEBUG] 5. After buildChangeDeletePendingData()`);

      let updated;
      try {
        updated = await prisma.$transaction(async (prisma) => {
          // Read current balance INSIDE the transaction
        const currentBook = await prisma.book.findUnique({ where: { id: book.id }, select: { balance: true } });
        let preTxnBalance = currentBook.balance;
        if (txn.type === 'expense') {
          preTxnBalance += txn.amount;
        } else if (txn.type === 'income') {
          preTxnBalance -= txn.amount;
        }

        console.log(`[DEBUG] 6. Before prisma.transaction.update()`);
        const editUpdateData = {
          ...changes,
          pendingAction: 'edit',
          pendingData,
          updateHistory: [
            ...(txn.updateHistory || []),
            {
              timestamp: new Date().toISOString(),
              userId: req.user.id,
              userName: user?.name || 'Unknown',
              action: 'edit_request',
              changes: { old: { amount: txn.amount, type: txn.type, category: txn.category, note: txn.note }, new: changes },
            },
          ],
        };
        // New flow for Send: keep reconStatus as 'approved', use pendingAction
        // Old flow for non-Send: set reconStatus to 'pending'
        if (!isSend) {
          editUpdateData.reconStatus = 'pending';
        }
        const updatedTxn = await prisma.transaction.update({
          where: { id: txnId },
          data: editUpdateData,
        });
        console.log(`[DEBUG] 7. After prisma.transaction.update()`);



        const linkedChanges = {};
        if (changes.amount !== undefined) linkedChanges.amount = parsedAmount;
        if (changes.note !== undefined) linkedChanges.note = changes.note;
        if (changes.category !== undefined) linkedChanges.category = changes.category;
        if (changes.contact !== undefined) linkedChanges.contact = changes.contact;
        if (changes.imageUrl !== undefined) linkedChanges.imageUrl = changes.imageUrl;
        if (changes.dateTime !== undefined) linkedChanges.dateTime = changes.dateTime;
        if (changes.fromLocation !== undefined) linkedChanges.fromLocation = changes.fromLocation;
        if (changes.toLocation !== undefined) linkedChanges.toLocation = changes.toLocation;

        console.log(`[DEBUG] 8. Before syncCounterpartLegsForChangeDelete()`);
        await syncCounterpartLegsForChangeDelete(prisma, txn, book, {
          pendingAction: 'edit',
          pendingData,
          fieldUpdates: linkedChanges,
          historyEntry: {
            timestamp: new Date().toISOString(),
            userId: req.user.id,
            userName: user?.name || 'Unknown',
            action: 'edit_request (counterpart)',
            changes: { new: linkedChanges }
          },
          reverseBalanceOnRequest: false, // Balance stays effective until approved
          keepReconStatus: isSend, // Send stays 'approved', uses pendingAction
        }, req.user.id);
        console.log(`[DEBUG] 9. After syncCounterpartLegsForChangeDelete()`);

        return updatedTxn;
      });
      } catch (err) {
        console.error('[DEBUG] 10. Error during pending edit transaction sync. Stack:', err.stack || err);
        return res.status(500).json({ error: 'Failed to process pending edit. Internal error.' });
      }

      broadcast({ type: 'data_changed' });
      await notifyChangeDeleteApprovers(updated, 'edit', pendingData);
      const enriched = await enrichTxn(updated);
      const summary = buildChangeDeleteNotification(pendingData, 'edit', updated);
      return res.json({
        transaction: enriched,
        pending: true,
        message: 'Edit submitted for approval',
        notification: summary,
      });
    }
  } catch (error) {
    console.error('[DEBUG] 10. Edit transaction outer catch block error. Stack:', error.stack || error);
    res.status(500).json({ error: 'Server error editing transaction' });
  }
});

// --- MODIFY PENDING TRANSACTION AMOUNT ---
// Recipient → sets counterProposedAmount (needs sender counter-approval)
// Sender/Admin → directly updates amount on both txns (no counter-approval needed)
app.post('/api/transactions/:id/modify', authenticateToken, async (req, res) => {
  try {
    const { amount: newAmount } = req.body;
    const txnId = req.params.id;

    if (!newAmount || parseFloat(newAmount) <= 0) {
      return res.status(400).json({ error: { bn: 'নতুন পরিমাণ একটি ধনাত্মক সংখ্যা হতে হবে।', en: 'New amount must be a positive number' } });
    }
    const parsedNew = parseFloat(newAmount);

    const txn = await prisma.transaction.findUnique({ where: { id: txnId } });
    if (!txn) return res.status(404).json({ error: { bn: 'লেনদেন পাওয়া যায়নি।', en: 'Transaction not found' } });
    if (!['pending', 'pending_org', 'pending_recipient'].includes(txn.reconStatus)) return res.status(400).json({ error: { bn: 'শুধু অপেক্ষমাণ লেনদেন পরিবর্তন করা যাবে।', en: 'Only pending transactions can be modified' } });

    // Determine if caller is the recipient or an admin/editor
    const txnBook = await prisma.book.findUnique({ where: { id: txn.bookId }, include: { organization: true } });
    if (!txnBook) return res.status(404).json({ error: { bn: 'বই পাওয়া যায়নি।', en: 'Book not found' } });

    // Recipient check: if txn is in user's personal book, they own it
    const memberCheck = await prisma.organizationMember.findFirst({
      where: { userId: req.user.id, organizationId: txnBook.organizationId, role: 'admin', status: 'active' }
    });
    const isPersonalBookOwner = txnBook.organization.isPersonal && !!memberCheck;
    const isRecipient = isPersonalBookOwner || txn.recipientUserId === req.user.id;
    const isEditor = await hasAdminOrEditorAccess(txnBook.organizationId, req.user.id);

    if (!isRecipient && !isEditor) {
      return res.status(403).json({ error: { bn: 'শুধু প্রাপক বা অ্যাডমিন/এডিটর পরিমাণ পরিবর্তন করতে পারেন।', en: 'Only the recipient or an admin/editor can modify the amount' } });
    }

    // Sender/Admin: directly update the amount on both linked txns
    if (isEditor && !isRecipient) {
      const updates = [];
      const clearData = { counterProposedAmount: null, counterProposedBy: null };
      updates.push(
        prisma.transaction.update({
          where: { id: txnId },
          data: { amount: parsedNew, ...clearData }
        })
      );
      if (txn.linkedTransactionId) {
        updates.push(
          prisma.transaction.update({
            where: { id: txn.linkedTransactionId },
            data: { amount: parsedNew, ...clearData }
          })
        );
      }
      await prisma.$transaction(updates);

      // Notify the recipient about the amount change
      if (txn.recipientUserId && txn.recipientUserId !== req.user.id) {
        broadcastToUser(txn.recipientUserId, { type: 'amount_modified' });
      }

      broadcast({ type: "data_changed" });
      return res.json({ message: 'Amount updated directly', amount: parsedNew });
    }

    // Recipient: set counter-proposal (needs sender counter-approval)
    await prisma.transaction.update({
      where: { id: txnId },
      data: { counterProposedAmount: parsedNew, counterProposedBy: req.user.id }
    });

    if (txn.linkedTransactionId) {
      await prisma.transaction.update({
        where: { id: txn.linkedTransactionId },
        data: { counterProposedAmount: parsedNew, counterProposedBy: req.user.id }
      });
    }

    // Notify the sender that recipient modified the amount
    if (txn.linkedTransactionId) {
      const sourceTxn = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { createdById: true } });
      if (sourceTxn && sourceTxn.createdById && sourceTxn.createdById !== req.user.id) {
        broadcastToUser(sourceTxn.createdById, { type: 'amount_modified' });
      }
    }

    broadcast({ type: "data_changed" });
    return res.json({ message: 'Modification proposed, waiting for sender approval', counterProposedAmount: parsedNew });
  } catch (error) {
    console.error('Modify transaction error:', error);
    res.status(500).json({ error: 'Server error modifying transaction' });
  }
});
};
