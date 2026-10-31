# PhishShield AI — AI-Powered Phishing & Scam Detection Dashboard

**PhishShield AI** is a full-stack cybersecurity web application powered by **Google Gemini AI (`gemini-3.8-flash`)** and a transparent 23-rule cybersecurity engine to help users identify dangerous emails, SMS messages, and deceptive URLs before interacting with them.

## Key Features

- **Live Google Gemini AI Analysis (`server.ts`)**: Connects directly to your Google Gemini account via the `@google/genai` SDK on the secure backend server to evaluate suspicious wording, psychological manipulation tactics, and deceptive URLs.
- **Hybrid Rule Engine + Fallback (`src/utils/phishingRules.ts`)**: Combines Gemini AI's structured risk assessment with 23 deterministic cybersecurity checks (urgency, credential harvesting, MFA/OTP interception, BEC wire fraud, raw IP hosts, `@` redirects, Punycode homographs, and brand spoofing), automatically falling back to rule-based scoring if the AI service is ever unreachable.
- **Zero-Visit URL Scanner**: Inspects URL structure without ever opening or visiting the submitted link.
- **Privacy-Preserving Scan History (`src/utils/serverDb.ts`)**: Automatically masks OTPs, CVVs, payment card numbers, email addresses, and phone numbers before analyzing and storing scan summaries.
