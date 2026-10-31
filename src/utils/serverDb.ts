import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
import type { ScanHistoryItem, ScanAnalysisResult } from './phishingRules.ts';
import { createInitialSeedHistory } from '../data/sampleScans.ts';

const require = createRequire(import.meta.url);

const DATA_DIR = path.resolve(process.cwd(), '.data');
const SQLITE_FILE = path.join(DATA_DIR, 'phishshield.sqlite');
const JSON_FALLBACK_FILE = path.join(DATA_DIR, 'phishshield-db.json');
const DB_SCHEMA_VERSION = 'clean_saas_v4';

interface SqliteStatement {
  run: (...params: unknown[]) => unknown;
  get: (...params: unknown[]) => Record<string, unknown> | undefined;
  all: (...params: unknown[]) => Array<Record<string, unknown>>;
}

interface SqliteDatabase {
  exec: (sql: string) => void;
  prepare: (sql: string) => SqliteStatement;
}

let sqliteDb: SqliteDatabase | null = null;
let sqliteInitAttempted = false;

function getSqliteDb(): SqliteDatabase | null {
  if (sqliteInitAttempted) {
    return sqliteDb;
  }
  sqliteInitAttempted = true;

  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    const sqliteModule = require('node:sqlite') as {
      DatabaseSync: new (filename: string) => SqliteDatabase;
    };
    const db = new sqliteModule.DatabaseSync(SQLITE_FILE);

    db.exec(`
      CREATE TABLE IF NOT EXISTS scan_history (
        id TEXT PRIMARY KEY,
        scan_type TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        risk_category TEXT NOT NULL,
        privacy_safe_snippet TEXT NOT NULL,
        indicator_count INTEGER NOT NULL,
        analysis_engine TEXT NOT NULL,
        full_result_json TEXT NOT NULL,
        created_order INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS scan_cache (
        cache_key TEXT PRIMARY KEY,
        result_json TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS app_meta (
        meta_key TEXT PRIMARY KEY,
        meta_value TEXT NOT NULL
      );
    `);

    const seededRow = db
      .prepare('SELECT meta_value FROM app_meta WHERE meta_key = ?')
      .get('schema_version');

    if (!seededRow || seededRow.meta_value !== DB_SCHEMA_VERSION) {
      db.exec('DELETE FROM scan_history; DELETE FROM scan_cache;');
      const upsertMeta = db.prepare(`
        INSERT OR REPLACE INTO app_meta (meta_key, meta_value) VALUES (?, ?)
      `);
      upsertMeta.run('schema_version', DB_SCHEMA_VERSION);
      upsertMeta.run('total_scans_ever', '0');
    }

    sqliteDb = db;
    return sqliteDb;
  } catch (err) {
    console.warn('[PhishShield DB] SQLite unavailable, using JSON store:', err);
    sqliteDb = null;
    return null;
  }
}

function readHistoryRowsFromSqlite(db: SqliteDatabase): ScanHistoryItem[] {
  const rows = db
    .prepare(
      `SELECT id, scan_type, timestamp, risk_score, risk_category,
              privacy_safe_snippet, indicator_count, analysis_engine, full_result_json
       FROM scan_history
       ORDER BY created_order DESC
       LIMIT 30`
    )
    .all();

  const items: ScanHistoryItem[] = [];
  for (const row of rows) {
    try {
      const fullResult = JSON.parse(String(row.full_result_json)) as ScanAnalysisResult;
      items.push({
        id: String(row.id),
        scanType: row.scan_type === 'url' ? 'url' : 'message',
        timestamp: String(row.timestamp),
        riskScore: Number(row.risk_score),
        riskCategory: fullResult.riskCategory,
        privacySafeSnippet: String(row.privacy_safe_snippet),
        indicatorCount: Number(row.indicator_count),
        analysisEngine: fullResult.analysisEngine,
        fullResult,
      });
    } catch {
      // Skip malformed row
    }
  }
  return items;
}

interface FallbackJsonSchema {
  history: ScanHistoryItem[];
  cache: Record<string, ScanAnalysisResult>;
  totalScansEver: number;
}

function ensureFallbackJson(): FallbackJsonSchema {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    if (fs.existsSync(JSON_FALLBACK_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(JSON_FALLBACK_FILE, 'utf-8')) as FallbackJsonSchema;
      if (parsed && Array.isArray(parsed.history)) {
        return parsed;
      }
    }
  } catch {
    // ignore
  }
  const initialHistory = createInitialSeedHistory();
  const initial: FallbackJsonSchema = {
    history: initialHistory,
    cache: {},
    totalScansEver: initialHistory.length,
  };
  fs.writeFileSync(JSON_FALLBACK_FILE, JSON.stringify(initial, null, 2), 'utf-8');
  return initial;
}

export function getHistoryFromDb(): {
  history: ScanHistoryItem[];
  totalScansEver: number;
} {
  const db = getSqliteDb();
  if (db) {
    const history = readHistoryRowsFromSqlite(db);
    const totalRow = db
      .prepare('SELECT meta_value FROM app_meta WHERE meta_key = ?')
      .get('total_scans_ever');
    const totalScansEver = totalRow ? Number(totalRow.meta_value) || history.length : history.length;
    return { history, totalScansEver };
  }

  const fallback = ensureFallbackJson();
  return {
    history: fallback.history,
    totalScansEver: fallback.totalScansEver,
  };
}

export function getCachedResult(cacheKey: string): ScanAnalysisResult | null {
  const db = getSqliteDb();
  if (db) {
    const row = db
      .prepare('SELECT result_json FROM scan_cache WHERE cache_key = ?')
      .get(cacheKey);
    if (!row || !row.result_json) return null;
    try {
      return JSON.parse(String(row.result_json)) as ScanAnalysisResult;
    } catch {
      return null;
    }
  }

  const fallback = ensureFallbackJson();
  return fallback.cache[cacheKey] || null;
}

export function recordScanInDb(cacheKey: string, result: ScanAnalysisResult): ScanHistoryItem[] {
  const db = getSqliteDb();
  if (db) {
    const nowOrder = Date.now();
    db.prepare(
      `INSERT OR REPLACE INTO scan_history (
        id, scan_type, timestamp, risk_score, risk_category,
        privacy_safe_snippet, indicator_count, analysis_engine,
        full_result_json, created_order
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      result.id,
      result.scanType,
      result.timestamp,
      result.riskScore,
      result.riskCategory,
      result.privacySafeSnippet,
      result.indicators.length,
      result.analysisEngine,
      JSON.stringify(result),
      nowOrder
    );

    db.exec(`
      DELETE FROM scan_history
      WHERE id NOT IN (
        SELECT id FROM scan_history ORDER BY created_order DESC LIMIT 30
      );
    `);

    if (result.analysisEngine === 'hybrid-gemini-and-rules') {
      db.prepare(
        `INSERT OR REPLACE INTO scan_cache (cache_key, result_json, updated_at)
         VALUES (?, ?, ?)`
      ).run(cacheKey, JSON.stringify(result), result.timestamp);
    }

    const totalRow = db
      .prepare('SELECT meta_value FROM app_meta WHERE meta_key = ?')
      .get('total_scans_ever');
    const nextTotal = (totalRow ? Number(totalRow.meta_value) || 0 : 0) + 1;
    db.prepare(
      `INSERT OR REPLACE INTO app_meta (meta_key, meta_value) VALUES (?, ?)`
    ).run('total_scans_ever', String(nextTotal));

    return readHistoryRowsFromSqlite(db);
  }

  const fallback = ensureFallbackJson();
  const historyItem: ScanHistoryItem = {
    id: result.id,
    scanType: result.scanType,
    timestamp: result.timestamp,
    riskScore: result.riskScore,
    riskCategory: result.riskCategory,
    privacySafeSnippet: result.privacySafeSnippet,
    indicatorCount: result.indicators.length,
    analysisEngine: result.analysisEngine,
    fullResult: result,
  };
  if (result.analysisEngine === 'hybrid-gemini-and-rules') {
    fallback.cache[cacheKey] = result;
  }
  fallback.history = [historyItem, ...fallback.history.filter((h) => h.id !== result.id)].slice(0, 30);
  fallback.totalScansEver = (fallback.totalScansEver || 0) + 1;
  fs.writeFileSync(JSON_FALLBACK_FILE, JSON.stringify(fallback, null, 2), 'utf-8');
  return fallback.history;
}

export function clearHistoryInDb(): ScanHistoryItem[] {
  const db = getSqliteDb();
  if (db) {
    db.exec('DELETE FROM scan_history; DELETE FROM scan_cache;');
    return [];
  }

  const fallback = ensureFallbackJson();
  fallback.history = [];
  fallback.cache = {};
  fs.writeFileSync(JSON_FALLBACK_FILE, JSON.stringify(fallback, null, 2), 'utf-8');
  return [];
}

export function restoreSeedHistoryInDb(): ScanHistoryItem[] {
  const seeded = createInitialSeedHistory();
  const db = getSqliteDb();
  if (db) {
    db.exec('DELETE FROM scan_history;');
    const insertHistory = db.prepare(`
      INSERT OR REPLACE INTO scan_history (
        id, scan_type, timestamp, risk_score, risk_category,
        privacy_safe_snippet, indicator_count, analysis_engine,
        full_result_json, created_order
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const baseOrder = Date.now();
    seeded.forEach((item, index) => {
      insertHistory.run(
        item.id,
        item.scanType,
        item.timestamp,
        item.riskScore,
        item.riskCategory,
        item.privacySafeSnippet,
        item.indicatorCount,
        item.analysisEngine,
        JSON.stringify(item.fullResult),
        baseOrder - index
      );
    });
    return readHistoryRowsFromSqlite(db);
  }

  const fallback = ensureFallbackJson();
  fallback.history = seeded;
  fs.writeFileSync(JSON_FALLBACK_FILE, JSON.stringify(fallback, null, 2), 'utf-8');
  return fallback.history;
}
