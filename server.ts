import 'dotenv/config';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI, Type, ThinkingLevel } from '@google/genai';
import {
  analyzeMessageRules,
  inspectUrlStructure,
  buildFinalScanResult,
  detectAndRedactSensitiveInput,
  type GeminiStructuredAssessment,
  type DetectedIndicator,
} from './src/utils/phishingRules.ts';
import {
  getHistoryFromDb,
  recordScanInDb,
  clearHistoryInDb,
  restoreSeedHistoryInDb,
} from './src/utils/serverDb.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;
const AI_TIMEOUT_MS = 5000;

function getGeminiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY' || apiKey.trim() === '') {
    return null;
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

const RESPONSE_SCHEMA = {
  type: Type.OBJECT,
  properties: {
    aiRiskScore: {
      type: Type.INTEGER,
      description: 'Risk score from 0 to 100. 0-29 is Lower Indicators, 30-59 is Suspicious, 60-100 is High Risk.',
    },
    summary: {
      type: Type.STRING,
      description: 'Friendly, plain-English 2-sentence explanation of why this input looks safe, suspicious, or high risk.',
    },
    warningSigns: {
      type: Type.ARRAY,
      items: { type: Type.STRING },
    },
    suspiciousPhrases: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        properties: {
          phrase: { type: Type.STRING },
          tactic: { type: Type.STRING },
          whySuspicious: { type: Type.STRING },
        },
        required: ['phrase', 'tactic', 'whySuspicious'],
      },
    },
    additionalIndicators: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        properties: {
          title: { type: Type.STRING },
          severity: { type: Type.STRING },
          category: { type: Type.STRING },
          matchedSnippet: { type: Type.STRING },
          explanation: { type: Type.STRING },
        },
        required: ['title', 'severity', 'category', 'explanation'],
      },
    },
    recommendedActions: {
      type: Type.ARRAY,
      items: { type: Type.STRING },
    },
    uncertaintyNote: {
      type: Type.STRING,
    },
  },
  required: [
    'aiRiskScore',
    'summary',
    'warningSigns',
    'suspiciousPhrases',
    'additionalIndicators',
    'recommendedActions',
    'uncertaintyNote',
  ],
};

async function runGeminiPhishingAnalysis(
  scanType: 'message' | 'url',
  redactedContent: string,
  ruleScore: number,
  ruleIndicators: DetectedIndicator[]
): Promise<{ assessment: GeminiStructuredAssessment | null; fallbackReason?: string }> {
  const ai = getGeminiClient();
  if (!ai) {
    return {
      assessment: null,
      fallbackReason: 'Gemini API key is not configured in environment — used deterministic rule-based fallback.',
    };
  }

  const ruleContext =
    ruleIndicators.length > 0
      ? ruleIndicators.map((r) => `- ${r.title} (${r.severity}): ${r.explanation}`).join('\n')
      : 'No deterministic rules triggered.';

  const prompt =
    scanType === 'message'
      ? `Analyze this email or SMS message for phishing, social engineering, or scam indicators.
Rule Engine Score: ${ruleScore}/100
Triggered Rules:
${ruleContext}

Submitted Message:
"""
${redactedContent}
"""`
      : `Statically inspect this URL structure for phishing, domain spoofing, or deceptive routing without visiting the URL.
Rule Engine Score: ${ruleScore}/100
Triggered URL Rules:
${ruleContext}

Submitted URL:
"""
${redactedContent}
"""`;

  try {
    const geminiPromise = ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        systemInstruction:
          'You are PhishShield AI, an expert cybersecurity assistant powered by Google Gemini. Analyze emails, SMS messages, and URLs for phishing indicators, explain suspicious wording in friendly plain English, calibrate aiRiskScore (0-29 Lower Indicators, 30-59 Suspicious, 60-100 High Risk), and clearly communicate uncertainty.',
        responseMimeType: 'application/json',
        responseSchema: RESPONSE_SCHEMA,
        thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
      },
    });

    const timeoutPromise = new Promise<null>((resolve) =>
      setTimeout(() => resolve(null), AI_TIMEOUT_MS)
    );

    const response = await Promise.race([geminiPromise, timeoutPromise]);
    if (!response) {
      return {
        assessment: null,
        fallbackReason: 'Gemini AI request timed out — completed scan using rule-based fallback engine.',
      };
    }

    const text = (response.text ?? '').trim();
    if (!text) {
      return {
        assessment: null,
        fallbackReason: 'Gemini AI returned an empty response — completed scan using rule-based fallback engine.',
      };
    }

    const parsed = JSON.parse(text) as GeminiStructuredAssessment;
    if (Array.isArray(parsed.additionalIndicators)) {
      parsed.additionalIndicators = parsed.additionalIndicators.map((ind) => ({
        ...ind,
        severity: ['low', 'medium', 'high'].includes(String(ind.severity).toLowerCase())
          ? (String(ind.severity).toLowerCase() as 'low' | 'medium' | 'high')
          : 'medium',
      }));
    }

    return { assessment: parsed };
  } catch (err) {
    console.warn('[PhishShield AI] Gemini API call error, falling back to rules:', err);
    return {
      assessment: null,
      fallbackReason: 'Gemini AI service temporarily unavailable — completed scan using rule-based fallback.',
    };
  }
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '64kb' }));

  app.get('/api/health', (_req, res) => {
    const { history, totalScansEver } = getHistoryFromDb();
    res.json({
      status: 'ok',
      service: 'PhishShield AI Security API',
      aiConfigured: Boolean(getGeminiClient()),
      model: 'gemini-3.8-flash',
      historyCount: history.length,
      totalScansEver,
    });
  });

  app.get('/api/history', (_req, res) => {
    const { history, totalScansEver } = getHistoryFromDb();
    res.json({
      history,
      totalScansEver,
      aiConfigured: Boolean(getGeminiClient()),
      model: 'gemini-3.8-flash',
    });
  });

  app.delete('/api/history', (_req, res) => {
    const history = clearHistoryInDb();
    res.json({ history });
  });

  app.post('/api/history/restore', (_req, res) => {
    const history = restoreSeedHistoryInDb();
    res.json({ history });
  });

  app.post('/api/scan/message', async (req, res) => {
    try {
      const { message } = req.body ?? {};
      if (typeof message !== 'string' || message.trim().length === 0) {
        res.status(400).json({
          error: 'Please paste an email or SMS message to scan.',
        });
        return;
      }

      const trimmed = message.trim();
      if (trimmed.length < 6) {
        res.status(400).json({
          error: 'Please enter at least 6 characters so we have enough text to check.',
        });
        return;
      }

      if (trimmed.length > 8000) {
        res.status(400).json({
          error: 'Message exceeds the 8,000 character safety limit.',
        });
        return;
      }

      const sensitiveCheck = detectAndRedactSensitiveInput(trimmed);
      const safeContent = sensitiveCheck.redactedText;
      const cacheKey = `message:gemini:${safeContent.slice(0, 240)}`;

      const ruleAnalysis = analyzeMessageRules(safeContent);
      const { assessment, fallbackReason } = await runGeminiPhishingAnalysis(
        'message',
        safeContent,
        ruleAnalysis.ruleScore,
        ruleAnalysis.indicators
      );

      const result = buildFinalScanResult({
        id: `scan-msg-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        scanType: 'message',
        rawInput: safeContent,
        ruleScore: ruleAnalysis.ruleScore,
        ruleIndicators: ruleAnalysis.indicators,
        rulePhrases: ruleAnalysis.suspiciousPhrases,
        urlBreakdown: ruleAnalysis.urlBreakdown,
        aiAssessment: assessment,
        fallbackReason,
      });

      const history = recordScanInDb(cacheKey, result);

      res.json({
        result,
        history,
        sensitiveDataRedacted: sensitiveCheck.hasSensitiveData,
        redactedTypes: sensitiveCheck.detectedTypes,
      });
    } catch (error: unknown) {
      console.error('[PhishShield AI] Error in /api/scan/message:', error);
      res.status(500).json({
        error: 'An unexpected error occurred while analyzing the message.',
      });
    }
  });

  app.post('/api/scan/url', async (req, res) => {
    try {
      const { url } = req.body ?? {};
      if (typeof url !== 'string' || url.trim().length === 0) {
        res.status(400).json({
          error: 'Please enter a URL or domain to inspect.',
        });
        return;
      }

      const trimmed = url.trim();
      if (trimmed.length < 4 || (!trimmed.includes('.') && !trimmed.includes(':') && !trimmed.includes('/'))) {
        res.status(400).json({
          error: 'Please enter a valid web address (for example: https://example.com/login).',
        });
        return;
      }

      if (trimmed.length > 2048) {
        res.status(400).json({
          error: 'URL exceeds the maximum 2,048 character length.',
        });
        return;
      }

      const cacheKey = `url:gemini:${trimmed.toLowerCase()}`;
      const urlRuleAnalysis = inspectUrlStructure(trimmed);
      const { assessment, fallbackReason } = await runGeminiPhishingAnalysis(
        'url',
        trimmed,
        urlRuleAnalysis.ruleScore,
        urlRuleAnalysis.indicators
      );

      const result = buildFinalScanResult({
        id: `scan-url-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        scanType: 'url',
        rawInput: trimmed,
        ruleScore: urlRuleAnalysis.ruleScore,
        ruleIndicators: urlRuleAnalysis.indicators,
        rulePhrases: urlRuleAnalysis.suspiciousPhrases,
        urlBreakdown: urlRuleAnalysis.breakdown,
        aiAssessment: assessment,
        fallbackReason,
      });

      const history = recordScanInDb(cacheKey, result);
      res.json({ result, history });
    } catch (error: unknown) {
      console.error('[PhishShield AI] Error in /api/scan/url:', error);
      res.status(500).json({
        error: 'An unexpected error occurred while inspecting the URL structure.',
      });
    }
  });

  if (process.env.NODE_ENV === 'production') {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`PhishShield AI server listening on http://localhost:${PORT}`);
  });
}

startServer();
