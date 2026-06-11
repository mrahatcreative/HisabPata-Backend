const { authenticateToken } = require('../../middleware/auth');
const {
  loadUserAiConfig,
  resolveAiRequestConfig,
  prepareAiAgentRequest,
  truncateAiMessagesForLlm,
  tryDeterministicAiResponse,
  resolveAiMaxTokens,
  buildGeminiRequestUrl,
  safeFetchJson,
  geminiTextFromResponse,
  isGeminiThinkingModel,
  finalizeAiAgentResponse,
  emitAiStreamFinal,
  saveAiChatTurn,
  getLastUserMessage,
} = require('./utils');

module.exports = function(app) {

app.post('/api/ai/agent', authenticateToken, async (req, res) => {
  try {
    const storedConfig = await loadUserAiConfig(req.user.id);
    const resolved = resolveAiRequestConfig(req.body, storedConfig);
    const { provider, apiKey, model, baseUrl, messages, bookId, orgId, temperature, maxTokens } = {
      ...req.body,
      provider: resolved.provider,
      apiKey: resolved.apiKey,
      model: resolved.model,
      baseUrl: resolved.baseUrl,
      temperature: resolved.temperature,
      maxTokens: resolved.maxTokens,
    };

    if (!provider || !apiKey || !messages) {
      return res.status(400).json({ error: 'Missing required fields: provider, apiKey, messages' });
    }
    if (!model || !String(model).trim()) {
      return res.status(400).json({
        error: 'AI model is not selected. Run Find Working Models in AI settings, pick a model, and save.',
      });
    }

    const agentCtx = await prepareAiAgentRequest(req.user.id, bookId, messages);
    const { systemPrompt, contextBookId, intent, serverToolData, recommendedTemperature } = agentCtx;
    const llmMessages = truncateAiMessagesForLlm(messages);

    const deterministic = await tryDeterministicAiResponse(messages, agentCtx, req.user.id);
    if (deterministic.handled) {
      await saveAiChatTurn({
        userId: req.user.id,
        userMessage: getLastUserMessage(messages),
        assistantMessage: deterministic.cleanResponse,
        bookId: contextBookId,
        model,
        provider,
        intent,
      });
      return res.json({
        response: deterministic.cleanResponse,
        proposedActions: deterministic.proposedActions || [],
      });
    }

    const tempVal = temperature != null ? parseFloat(temperature) : recommendedTemperature;
    const maxTokVal = resolveAiMaxTokens(maxTokens, model, provider);

    let aiResponseText = '';

    if (provider === 'gemini') {
      const url = buildGeminiRequestUrl(baseUrl, model, 'generate', apiKey);

      const contents = llmMessages.map(m => ({
        role: m.role === 'user' ? 'user' : 'model',
        parts: [{ text: m.content }]
      }));

      const geminiRes = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents,
          systemInstruction: { parts: [{ text: systemPrompt }] },
          generationConfig: { temperature: tempVal, maxOutputTokens: maxTokVal }
        })
      });
      const geminiData = await safeFetchJson(geminiRes);
      if (!geminiRes.ok) {
        return res.status(geminiRes.status).json({ error: geminiData.error?.message || 'Gemini API Error' });
      }
      aiResponseText = geminiTextFromResponse(geminiData);

    } else if (provider === 'openai') {
      const url = baseUrl ? `${baseUrl}/v1/chat/completions` : 'https://api.openai.com/v1/chat/completions';
      const formattedMessages = [
        { role: 'system', content: systemPrompt },
        ...llmMessages.map(m => ({ role: m.role, content: m.content }))
      ];

      const openaiRes = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({ model, messages: formattedMessages, temperature: tempVal, max_tokens: maxTokVal })
      });
      const openaiData = await openaiRes.json();
      if (!openaiRes.ok) {
        return res.status(openaiRes.status).json({ error: openaiData.error?.message || 'OpenAI API Error' });
      }
      aiResponseText = openaiData.choices?.[0]?.message?.content || '';

    } else if (provider === 'claude') {
      const url = baseUrl ? `${baseUrl}/v1/messages` : 'https://api.anthropic.com/v1/messages';
      const claudeRes = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model,
          max_tokens: maxTokVal,
          temperature: tempVal,
          system: systemPrompt,
          messages: llmMessages.map(m => ({ role: m.role, content: m.content }))
        })
      });
      const claudeData = await claudeRes.json();
      if (!claudeRes.ok) {
        return res.status(claudeRes.status).json({ error: claudeData.error?.message || 'Claude API Error' });
      }
      aiResponseText = claudeData.content?.[0]?.text || '';

    } else {
      return res.status(400).json({ error: 'Unsupported provider' });
    }

    const { cleanResponse, proposedActions } = await finalizeAiAgentResponse(aiResponseText, {
      contextBookId,
      userId: req.user.id,
      intent,
      serverToolData,
      messages,
    });

    await saveAiChatTurn({
      userId: req.user.id,
      userMessage: getLastUserMessage(messages),
      assistantMessage: cleanResponse,
      bookId: contextBookId,
      model,
      provider,
      intent,
    });

    return res.json({
      response: cleanResponse,
      proposedActions,
    });

  } catch (error) {
    console.error('[AI Agent] Error:', error);
    const detail = error?.message || 'Internal server error';
    res.status(500).json({ error: detail });
  }
});

app.post('/api/ai/agent/stream', authenticateToken, async (req, res) => {
  try {
    const storedConfig = await loadUserAiConfig(req.user.id);
    const resolved = resolveAiRequestConfig(req.body, storedConfig);
    const { provider, apiKey, model, baseUrl, messages, bookId, orgId, temperature, maxTokens } = {
      ...req.body,
      provider: resolved.provider,
      apiKey: resolved.apiKey,
      model: resolved.model,
      baseUrl: resolved.baseUrl,
      temperature: resolved.temperature,
      maxTokens: resolved.maxTokens,
    };

    if (!provider || !apiKey || !messages) {
      return res.status(400).json({ error: 'Missing required fields: provider, apiKey, messages' });
    }
    if (!model || !String(model).trim()) {
      return res.status(400).json({
        error: 'AI model is not selected. Run Find Working Models in AI settings, pick a model, and save.',
      });
    }

    const agentCtx = await prepareAiAgentRequest(req.user.id, bookId, messages);
    const { systemPrompt, contextBookId, intent, recommendedTemperature } = agentCtx;
    const llmMessages = truncateAiMessagesForLlm(messages);

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const sendEvent = (type, data) => {
      res.write(`data: ${JSON.stringify({ type, ...data })}\n\n`);
    };

    const deterministic = await tryDeterministicAiResponse(messages, agentCtx, req.user.id);
    if (deterministic.handled) {
      await saveAiChatTurn({
        userId: req.user.id,
        userMessage: getLastUserMessage(messages),
        assistantMessage: deterministic.cleanResponse,
        bookId: contextBookId,
        model,
        provider,
        intent,
      });
      sendEvent('clean', { response: deterministic.cleanResponse });
      if (deterministic.proposedActions?.length) {
        sendEvent('actions', { actions: deterministic.proposedActions });
      }
      sendEvent('done', {});
      return res.end();
    }

    const tempVal = temperature != null ? parseFloat(temperature) : recommendedTemperature;
    const maxTokVal = resolveAiMaxTokens(maxTokens, model, provider);

    if (provider === 'gemini') {
      const url = buildGeminiRequestUrl(baseUrl, model, 'stream', apiKey);

      const contents = llmMessages.map(m => ({
        role: m.role === 'user' ? 'user' : 'model',
        parts: [{ text: m.content }]
      }));

      const geminiRes = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents,
          systemInstruction: { parts: [{ text: systemPrompt }] },
          generationConfig: { temperature: tempVal, maxOutputTokens: maxTokVal }
        })
      });

      if (!geminiRes.ok) {
        const errData = await safeFetchJson(geminiRes);
        sendEvent('error', { message: errData.error?.message || 'Gemini API Error' });
        sendEvent('done', {});
        return res.end();
      }

      let fullText = '';

      if (!geminiRes.body) {
        const data = await safeFetchJson(geminiRes);
        fullText = geminiTextFromResponse(data);
        if (fullText) sendEvent('chunk', { content: fullText });
      } else {
        const reader = geminiRes.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            if (!line.startsWith('data: ')) continue;
            try {
              const data = JSON.parse(line.slice(6));
              const text = geminiTextFromResponse(data);
              if (text) {
                fullText += text;
                sendEvent('chunk', { content: text });
              }
            } catch (e) { /* skip parse errors */ }
          }
        }
      }

      if (!fullText.trim()) {
        const fallbackUrl = buildGeminiRequestUrl(baseUrl, model, 'generate', apiKey);
        const fallbackRes = await fetch(fallbackUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents,
            systemInstruction: { parts: [{ text: systemPrompt }] },
            generationConfig: { temperature: tempVal, maxOutputTokens: maxTokVal },
          }),
        });
        const fallbackData = await safeFetchJson(fallbackRes);
        if (fallbackRes.ok) {
          fullText = geminiTextFromResponse(fallbackData);
          if (fullText) sendEvent('chunk', { content: fullText });
        }
      }

      if (!fullText.trim()) {
        const hint = isGeminiThinkingModel(model)
          ? 'Gemini 2.5+ needs higher Max Tokens (at least 2048). Open AI Settings, set Max Tokens to 2048 or higher, save, then retry.'
          : 'Gemini returned an empty response. Try another model from Find Working Models.';
        sendEvent('error', { message: hint });
        sendEvent('done', {});
        return res.end();
      }

      await emitAiStreamFinal(sendEvent, fullText, agentCtx, req.user.id, messages, { model, provider });

    } else if (provider === 'openai') {
      const url = baseUrl ? `${baseUrl}/v1/chat/completions` : 'https://api.openai.com/v1/chat/completions';
      const formattedMessages = [
        { role: 'system', content: systemPrompt },
        ...llmMessages.map(m => ({ role: m.role, content: m.content }))
      ];

      const openaiRes = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model,
          messages: formattedMessages,
          temperature: tempVal,
          max_tokens: maxTokVal,
          stream: true
        })
      });

      if (!openaiRes.ok) {
        const errData = await openaiRes.json();
        sendEvent('error', { message: errData.error?.message || 'OpenAI API Error' });
        sendEvent('done', {});
        return res.end();
      }

      const reader = openaiRes.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let fullText = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const jsonStr = line.slice(6).trim();
            if (jsonStr === '[DONE]') continue;
            try {
              const data = JSON.parse(jsonStr);
              const content = data.choices?.[0]?.delta?.content || '';
              if (content) {
                fullText += content;
                sendEvent('chunk', { content });
              }
            } catch (e) { /* skip */ }
          }
        }
      }

      await emitAiStreamFinal(sendEvent, fullText, agentCtx, req.user.id, messages, { model, provider });

    } else if (provider === 'claude') {
      const url = baseUrl ? `${baseUrl}/v1/messages` : 'https://api.anthropic.com/v1/messages';
      const claudeRes = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model,
          max_tokens: maxTokVal,
          temperature: tempVal,
          system: systemPrompt,
          messages: llmMessages.map(m => ({ role: m.role, content: m.content })),
          stream: true
        })
      });

      if (!claudeRes.ok) {
        const errData = await claudeRes.json();
        sendEvent('error', { message: errData.error?.message || 'Claude API Error' });
        sendEvent('done', {});
        return res.end();
      }

      const reader = claudeRes.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let fullText = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.slice(6));
              if (data.type === 'content_block_delta' && data.delta?.text) {
                fullText += data.delta.text;
                sendEvent('chunk', { content: data.delta.text });
              }
            } catch (e) { /* skip */ }
          }
        }
      }

      await emitAiStreamFinal(sendEvent, fullText, agentCtx, req.user.id, messages, { model, provider });

    } else {
      sendEvent('error', { message: `Unsupported provider: ${provider}` });
      sendEvent('done', {});
      return res.end();
    }

    sendEvent('done', {});
    res.end();

  } catch (error) {
    console.error('[AI Agent Stream] Error:', error);
    const detail = error?.message || 'Internal server error';
    if (!res.headersSent) {
      res.status(500).json({ error: detail });
    } else {
      res.write(`data: ${JSON.stringify({ type: 'error', message: detail })}\n\n`);
      res.end();
    }
  }
});

};
