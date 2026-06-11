const GEMINI_DEFAULT_BASE = 'https://generativelanguage.googleapis.com';
const AI_LLM_HISTORY_LIMIT = 6;
const AI_LLM_CONTENT_LIMIT = 1800;

const normalizeGeminiBaseUrl = (baseUrl) => {
  if (!baseUrl || typeof baseUrl !== 'string') return null;
  let base = baseUrl.trim().replace(/\/+$/, '');
  if (!base) return null;
  base = base.replace(/\/v1beta(\/.*)?$/i, '');
  return base;
};

const buildGeminiRequestUrl = (baseUrl, model, mode, apiKey) => {
  const base = normalizeGeminiBaseUrl(baseUrl) || GEMINI_DEFAULT_BASE;
  const endpoint = mode === 'stream' ? 'streamGenerateContent' : 'generateContent';
  const query = mode === 'stream'
    ? `alt=sse&key=${encodeURIComponent(apiKey)}`
    : `key=${encodeURIComponent(apiKey)}`;
  return `${base}/v1beta/models/${encodeURIComponent(model)}:${endpoint}?${query}`;
};

const safeFetchJson = async (res) => {
  const text = await res.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { error: { message: text.slice(0, 300) } };
  }
};

const geminiTextFromResponse = (data) => {
  const parts = data?.candidates?.[0]?.content?.parts;
  if (!Array.isArray(parts)) return '';
  return parts.map((p) => (typeof p?.text === 'string' ? p.text : '')).join('');
};

const isGeminiThinkingModel = (model) => /gemini-2\.5|gemini-3/i.test(String(model || ''));

const resolveAiMaxTokens = (maxTokens, model = '', provider = '') => {
  const parsed = maxTokens != null ? parseInt(maxTokens, 10) : 512;
  const safe = Number.isFinite(parsed) ? parsed : 512;
  if (provider === 'gemini' && isGeminiThinkingModel(model)) {
    return Math.min(Math.max(safe, 2048), 8192);
  }
  return Math.min(Math.max(safe, 256), 2048);
};

const truncateAiMessagesForLlm = (messages, maxCount = AI_LLM_HISTORY_LIMIT) => {
  if (!Array.isArray(messages)) return [];
  return messages.slice(-maxCount).map(m => ({
    role: m.role,
    content: String(m.content || '').slice(0, AI_LLM_CONTENT_LIMIT),
  }));
};

module.exports = {
  GEMINI_DEFAULT_BASE,
  AI_LLM_HISTORY_LIMIT,
  AI_LLM_CONTENT_LIMIT,
  normalizeGeminiBaseUrl,
  buildGeminiRequestUrl,
  safeFetchJson,
  geminiTextFromResponse,
  isGeminiThinkingModel,
  resolveAiMaxTokens,
  truncateAiMessagesForLlm,
};
