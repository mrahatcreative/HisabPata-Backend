const express = require('express');
const { AI_SERVER_URL } = require('../config/env');

const SYSTEM_PROMPT = `তুমি Hisab AI — M Rahat বানিয়েছেন।
তোমার উত্তর সবসময় শুধুমাত্র JSON format-এ দাও।
কোনো natural text, greeting, বা comment থাকবে না।

Examples:

user: 500 টাকা খরচ করেছি পরিবহন বাবদ
assistant: {"intent":"add_expense","slots":{"amount":500,"category":"Transport","account_type":"personal"},"action":"ask_confirm","missing_fields":[],"confidence":0.95,"response":"পরিবহন বাবদ ৫০০ টাকা খরচ যোগ করছি?"}

user: কে তুমি?
assistant: {"intent":"identity","slots":{},"action":"respond","missing_fields":[],"confidence":1.0,"response":"আমি Hisab AI — M Rahat বানিয়েছেন।"}

user: ব্যালেন্স কত?
assistant: {"intent":"check_balance","slots":{"account_type":"personal"},"action":"respond","missing_fields":[],"confidence":1.0,"response":"আপনার ব্যালেন্স ১২৫০০ টাকা।"}

user: রহিম কে ২০০ টাকা সেন্ড করেছি
assistant: {"intent":"send_money","slots":{"amount":200,"recipient":"রহিম","account_type":"personal"},"action":"ask_confirm","missing_fields":[],"confidence":0.9,"response":"রহিম কে ২০০ টাকা পাঠানোর নিশ্চিত?"}`;

const BALANCE_KW = ['ব্যালেন্স', 'balance', 'কত টাকা আছে', 'কত টাকা', 'বাকি কত', 'টাকা আছে কত'];
const GREETINGS = ['হাই', 'হ্যালো', 'hello', 'hi', 'hey', 'আসসালামু আলাইকুম', 'সালাম', 'bye', 'বাই', 'ধন্যবাদ', 'thanks'];
const IDENTITY_KW = ['কে তুমি', 'কে তোমাকে বানিয়েছে', 'তোমার বানানো', 'তোমার creator', 'কে বানিয়েছে'];

function ruleHandle(message, context) {
  const msg = message.toLowerCase().trim();

  if (GREETINGS.includes(msg)) {
    return { intent: 'greeting', slots: {}, action: 'respond', missing_fields: [], confidence: 1.0, response: 'হ্যালো! আমি Hisab AI — M Rahat বানিয়েছেন। বলুন কী করতে চান?' };
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

module.exports = (app) => {
  const router = express.Router();

  // POST /api/ai/chat — rule-first, then model
  router.post('/chat', async (req, res) => {
    try {
      const { message, context } = req.body;

      // Step 1: Try rule
      const ruled = ruleHandle(message, context);
      if (ruled) {
        return res.json({
          id: `chatcmpl-${Math.random().toString(36).slice(2, 14)}`,
          object: 'chat.completion',
          created: Math.floor(Date.now() / 1000),
          choices: [{ index: 0, message: { role: 'assistant', content: JSON.stringify(ruled) }, finish_reason: 'stop' }],
          usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
        });
      }

      // Step 2: Build OpenAI messages with system prompt
      let contextBlock = '';
      if (context) {
        const cats = context.categories?.length ? context.categories.join(', ') : 'Transport, Mobile Recharge, Postage, Publication, Office Stationery, Tips, Donation, Others, Salary';
        const bal = context.balance ?? 0;
        contextBlock = `\nbook_type: personal\ncategories: ${cats}\nbalance: ${bal}`;
      }

      const messages = [
        { role: 'system', content: SYSTEM_PROMPT + contextBlock },
        { role: 'user', content: message },
      ];

      const response = await fetch(`${AI_SERVER_URL}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages, max_tokens: 256, temperature: 0.1 }),
      });

      if (!response.ok) {
        return res.status(response.status).json({ error: `AI server error: ${response.statusText}` });
      }

      const data = await response.json();
      res.json(data);
    } catch (err) {
      console.error('[AI Proxy]', err.message);
      res.status(502).json({ error: 'AI server unreachable', detail: err.message });
    }
  });

  // POST /api/ai/expense/confirm
  router.post('/expense/confirm', async (_req, res) => {
    try {
      const response = await fetch(`${AI_SERVER_URL}/v1/expense/confirm`, { method: 'POST' });
      const data = await response.json();
      res.json(data);
    } catch (err) {
      res.status(502).json({ status: 'error', message: err.message });
    }
  });

  // POST /api/ai/expense/cancel
  router.post('/expense/cancel', async (_req, res) => {
    try {
      const response = await fetch(`${AI_SERVER_URL}/v1/expense/cancel`, { method: 'POST' });
      const data = await response.json();
      res.json(data);
    } catch (err) {
      res.status(502).json({ status: 'error', message: err.message });
    }
  });

  // GET /api/ai/health — AI server health check
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
