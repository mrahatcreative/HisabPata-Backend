const express = require('express');
const { AI_SERVER_URL } = require('../config/env');

const SYSTEM_PROMPT = `তুমি Hisab AI — একটি বাংলা আর্থিক সহায়ক।

তোমার উত্তর দুই ধরনের হতে পারে:

**JSON (শুধু লেনদেনের জন্য):**
খরচ যোগ → {"intent":"add_expense","slots":{"amount":500,"category":"Transport"},"action":"ask_confirm","response":"পরিবহন বাবদ ৫০০ টাকা খরচ যোগ করছি?"}
টাকা পাঠানো → {"intent":"send_money","slots":{"amount":200,"recipient":"রহিম"},"action":"ask_confirm","response":"রহিম কে ২০০ টাকা পাঠানোর নিশ্চিত?"}
ব্যালেন্স → {"intent":"check_balance","action":"respond","response":"আপনার ব্যালেন্স ১২৫০০ টাকা।"}
পরিচয় → {"intent":"identity","action":"respond","response":"আমি Hisab AI — M Rahat বানিয়েছেন।"}

**সাধারণ বাংলা (বিশ্লেষণ/কথোপকথনের জন্য):**
JSON ছাড়াই সরাসরি উত্তর দাও। নিচের ডাটা ব্যবহার করে বাস্তব তথ্যভিত্তিক বিশ্লেষণ করো:
- কোন ক্যাটাগরিতে কত খরচ হয়েছে
- কোনো নির্দিষ্ট সময়ে মোট আয়/খরচ
- বইগুলোর ব্যালেন্স তুলনা
- খরচের প্যাটার্ন ও পরিবর্তন

নিয়ম:
- "খরচ করেছি/দিয়েছি" → add_expense JSON
- "পাঠিয়েছি/সেন্ড করেছি" → send_money JSON
- "ব্যালেন্স/কত টাকা আছে" → check_balance JSON
- আর্থিক বিশ্লেষণ/তুলনা/পরামর্শ → সাধারণ বাংলা
- "কে বানিয়েছে" → "M Rahat বানিয়েছেন"
- অপ্রাসঙ্গিক প্রশ্ন → বাংলায় জানাও যে শুধু আর্থিক কাজে সাহায্য করতে পারো`;

const BALANCE_KW = ['ব্যালেন্স', 'balance', 'কত টাকা আছে', 'কত টাকা', 'বাকি কত', 'টাকা আছে কত'];
const GREETINGS = ['হাই', 'হ্যালো', 'hello', 'hi', 'hey', 'আসসালামু আলাইকুম', 'সালাম', 'bye', 'বাই', 'ধন্যবাদ', 'thanks'];
const IDENTITY_KW = ['কে তুমি', 'কে তোমাকে বানিয়েছে', 'তোমার বানানো', 'তোমার creator', 'কে বানিয়েছে'];

function ruleHandle(message, context) {
  const msg = message.toLowerCase().trim();

  if (GREETINGS.includes(msg)) {
    return { intent: 'greeting', slots: {}, action: 'respond', missing_fields: [], confidence: 1.0, response: 'হ্যালো! বলুন কী করতে চান?' };
  }

  if (IDENTITY_KW.some(kw => msg.includes(kw))) {
    return { intent: 'identity', slots: {}, action: 'respond', missing_fields: [], confidence: 1.0, response: 'আমি Hisab AI — M Rahat বানিয়েছেন।' };
  }

  if (BALANCE_KW.some(kw => msg.includes(kw))) {
    const balance = context?.balance ?? 0;
    return { intent: 'check_balance', slots: { account_type: 'personal' }, action: 'respond', missing_fields: [], confidence: 1.0, response: `আপনার বর্তমান ব্যালেন্স: ${Number(balance).toLocaleString('en-IN')} টাকা।` };
  }

  return null;
}

function jsonToContent(parsed) {
  const { response: text, slots, action, intent } = parsed;
  let extra = '';
  if (action === 'ask_confirm' && slots && Object.keys(slots).length > 0) {
    const expense = { type: 'expense', ...slots };
    extra = `\n\n[DATA type:expense]${JSON.stringify(expense)}[/DATA]`;
  }
  if (intent === 'check_balance' && slots?.balance != null) {
    const bal = slots.balance;
    const books = typeof bal === 'number' ? [{ book: 'Personal', balance: bal }] : bal;
    extra = `\n\n[DATA type:balance]${JSON.stringify({ books })}[/DATA]`;
  }
  return (text || '') + extra;
}

let pendingExpense = null;

console.log('[AI Routes] Loading /api/ai/* routes...');
module.exports = (app) => {
  const router = express.Router();

  router.post('/chat', async (req, res) => {
    try {
      const { messages: clientMessages, message, context } = req.body;

      const latestMsg = clientMessages?.length > 0
        ? clientMessages[clientMessages.length - 1]?.content || message || ''
        : message || '';

      const ruled = ruleHandle(latestMsg, context);
      if (ruled) {
        if (ruled.intent === 'add_expense' && ruled.action === 'ask_confirm') {
          pendingExpense = { ...ruled.slots, type: 'expense' };
        }
        return res.json({
          id: `chatcmpl-${Math.random().toString(36).slice(2, 14)}`,
          object: 'chat.completion',
          created: Math.floor(Date.now() / 1000),
          choices: [{ index: 0, message: { role: 'assistant', content: jsonToContent(ruled) }, finish_reason: 'stop' }],
          usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
        });
      }

      let contextBlock = '';
      if (context) {
        const cats = context.categories?.length ? context.categories.join(', ') : 'Transport, Mobile Recharge, Postage, Publication, Office Stationery, Tips, Donation, Others, Salary';
        const bal = context.balance ?? 0;
        const bookName = context.book_name || 'Personal';
        contextBlock = `\nবর্তমান বই: "${bookName}"\nব্যালেন্স: ${bal} টাকা\nক্যাটাগরি: ${cats}`;

        if (context.recent_transactions?.length > 0) {
          let totalIncome = 0, totalExpense = 0;
          contextBlock += `\nসাম্প্রতিক লেনদেন (সর্বশেষ ২০টি):\n`;
          context.recent_transactions.forEach((t, i) => {
            const tType = t.type === 'expense' ? 'খরচ' : 'আয়';
            const tCat = t.category || '';
            const tNote = t.note ? ` (${t.note})` : '';
            const tAmt = t.amount ?? 0;
            const tDate = t.dateTime ? new Date(t.dateTime).toLocaleDateString('bn') : '';
            contextBlock += `${i + 1}. ${tType} ${tAmt}টাকা ${tCat}${tNote} ${tDate}\n`;
            if (t.type === 'expense') totalExpense += tAmt;
            else totalIncome += tAmt;
          });
          contextBlock += `\nসংক্ষিপ্ত: সর্বশেষ ২০ লেনদেনে মোট আয় ${totalIncome}টাকা, মোট খরচ ${totalExpense}টাকা`;
        }

        if (context.all_books?.length > 0) {
          contextBlock += `\nসব বই:\n`;
          context.all_books.forEach(b => {
            contextBlock += `- "${b.name}": ${b.balance} টাকা\n`;
          });
        }
      }

      const history = (clientMessages || []).slice(0, -1).filter(m => m.role === 'user' || m.role === 'assistant');
      const messages = [
        { role: 'system', content: SYSTEM_PROMPT + contextBlock },
        ...history,
        { role: 'user', content: latestMsg },
      ];

      const response = await fetch(`${AI_SERVER_URL}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages, max_tokens: 512, temperature: 0.3 }),
      });

      if (!response.ok) {
        return res.status(response.status).json({ error: `AI server error: ${response.statusText}` });
      }

      const data = await response.json();
      const rawContent = data?.choices?.[0]?.message?.content;
      if (rawContent) {
        try {
          const parsed = JSON.parse(rawContent);
          if (parsed.intent === 'add_expense' && parsed.action === 'ask_confirm') {
            pendingExpense = { ...parsed.slots, type: 'expense' };
          }
          data.choices[0].message.content = jsonToContent(parsed);
        } catch {
          // not valid JSON, leave as-is
        }
      }
      res.json(data);
    } catch (err) {
      console.error('[AI Proxy]', err.message);
      res.status(502).json({ error: 'AI server unreachable', detail: err.message });
    }
  });

  router.post('/expense/confirm', async (_req, res) => {
    if (!pendingExpense) {
      return res.status(400).json({ status: 'error', message: 'No pending expense' });
    }
    res.json({ status: 'ok', expense: pendingExpense });
    pendingExpense = null;
  });

  router.post('/expense/cancel', async (_req, res) => {
    pendingExpense = null;
    res.json({ status: 'ok', message: 'Cancelled' });
  });

  router.get('/health', async (_req, res) => {
    try {
      const response = await fetch(`${AI_SERVER_URL}/health`, { signal: AbortSignal.timeout(5000) });
      const data = await response.json();
      res.json(data);
    } catch {
      res.status(502).json({ status: 'error', model_online: false });
    }
  });

  app.use('/api/ai', router);
};
