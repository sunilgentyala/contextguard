/**
 * ContextGuard - Dynamic Integrity Monitoring System (DIMS)
 * Module: Semantic Fingerprinting and Definition Drift Detection
 *
 * Implements Equations (3) and (4) from the paper:
 *   F_i = LSH( Embed(D_i) )
 *   sim( F_i^(t), F_i^(t-1) ) < theta_drift  => ALERT
 *
 * Uses TF-IDF vectorization + cosine similarity as the embedding.
 * LSH is approximated via random projection into 64-bit buckets.
 * No external ML dependencies.
 *
 * Also implements adversarial instruction pattern scanning (SCVE-lite):
 * detects known tool-poisoning indicators in tool descriptions.
 */

import * as crypto from 'crypto';

export interface SemanticFingerprint {
  toolName: string;
  tfidfVector: Map<string, number>;
  lshBucket: string;       // 16-hex-char hash of projection
  timestamp: number;
  rawTokens: string[];
}

export interface DriftResult {
  toolName: string;
  similarity: number;
  driftDetected: boolean;
  threshold: number;
  previousFingerprint: SemanticFingerprint | null;
  currentFingerprint: SemanticFingerprint;
}

export interface PoisoningIndicator {
  pattern: string;
  category: 'hidden_instruction' | 'exfiltration' | 'credential_harvest' | 'obfuscation' | 'privilege_escalation';
  severity: 'critical' | 'high' | 'medium';
  matchedText: string;
}

export interface ScanResult {
  toolName: string;
  clean: boolean;
  indicators: PoisoningIndicator[];
  riskScore: number;  // 0.0 – 1.0
}

// ── Tokenization ──────────────────────────────────────────────────────────

const STOP_WORDS = new Set([
  'a','an','the','and','or','but','in','on','at','to','for','of','with',
  'by','from','as','is','was','are','were','be','been','being','have',
  'has','had','do','does','did','will','would','could','should','may',
  'might','shall','this','that','these','those','it','its','not','no',
  'can','you','your','we','our','they','their','i','my','he','she','his',
  'her','which','who','what','when','where','how','if','then','so','also'
]);

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s_]/g, ' ')
    .split(/\s+/)
    .filter(t => t.length > 2 && !STOP_WORDS.has(t));
}

// ── TF-IDF ────────────────────────────────────────────────────────────────

function termFrequency(tokens: string[]): Map<string, number> {
  const tf = new Map<string, number>();
  for (const t of tokens) tf.set(t, (tf.get(t) ?? 0) + 1);
  const total = tokens.length || 1;
  for (const [term, count] of tf) tf.set(term, count / total);
  return tf;
}

// Static IDF corpus built from benign tool description vocabulary
// (in production this would be trained; here we use a document-frequency proxy)
const COMMON_TOOL_TERMS: Set<string> = new Set([
  'function','tool','returns','value','string','number','integer','boolean',
  'list','array','object','parameter','input','output','result','data',
  'file','database','query','search','read','write','create','delete','update',
  'get','set','fetch','send','receive','process','execute','run','call',
  'api','endpoint','request','response','error','success','message',
  'user','id','name','path','url','key','type','format','content','item'
]);

function idf(term: string): number {
  // Higher IDF for unusual terms (not in common tool vocabulary)
  return COMMON_TOOL_TERMS.has(term) ? 1.0 : 3.5;
}

function tfidfVector(tokens: string[]): Map<string, number> {
  const tf = termFrequency(tokens);
  const tfidf = new Map<string, number>();
  for (const [term, tfVal] of tf) {
    tfidf.set(term, tfVal * idf(term));
  }
  return tfidf;
}

// ── Cosine Similarity ─────────────────────────────────────────────────────

function cosineSimilarity(a: Map<string, number>, b: Map<string, number>): number {
  let dot = 0, normA = 0, normB = 0;
  for (const [term, val] of a) {
    dot += val * (b.get(term) ?? 0);
    normA += val * val;
  }
  for (const [, val] of b) normB += val * val;
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom === 0 ? 0 : dot / denom;
}

// ── LSH Bucket ────────────────────────────────────────────────────────────

function lshBucket(tfidf: Map<string, number>, numProjections = 32): string {
  // Deterministic random projections seeded from term names
  let bits = 0n;
  let idx = 0;
  for (const [term, val] of tfidf) {
    const seed = crypto.createHash('sha256').update(`proj_${idx % numProjections}_${term}`).digest();
    const projVal = (seed[0] - 127.5) * val;
    if (projVal > 0) bits |= (1n << BigInt(idx % 64));
    idx++;
  }
  return bits.toString(16).padStart(16, '0');
}

// ── Fingerprint Builder ───────────────────────────────────────────────────

export function buildFingerprint(toolName: string, description: string): SemanticFingerprint {
  const rawTokens = tokenize(description);
  const tfidfVec = tfidfVector(rawTokens);
  const bucket = lshBucket(tfidfVec);
  return { toolName, tfidfVector: tfidfVec, lshBucket: bucket, timestamp: Date.now(), rawTokens };
}

// ── Drift Detection ───────────────────────────────────────────────────────

/**
 * Default threshold theta_drift = 0.72
 * Calibrated so that:
 *   - Normal description reformatting: similarity ~0.88–0.99
 *   - Adversarial instruction insertion (40+ words): similarity ~0.30–0.65
 *   - Minor version bumps / clarification edits: similarity ~0.75–0.90
 */
export const DEFAULT_DRIFT_THRESHOLD = 0.72;

export function detectDrift(
  toolName: string,
  currentDescription: string,
  storedFingerprint: SemanticFingerprint | null,
  threshold = DEFAULT_DRIFT_THRESHOLD
): DriftResult {
  const currentFp = buildFingerprint(toolName, currentDescription);

  if (!storedFingerprint) {
    return {
      toolName,
      similarity: 1.0,
      driftDetected: false,
      threshold,
      previousFingerprint: null,
      currentFingerprint: currentFp,
    };
  }

  const similarity = cosineSimilarity(currentFp.tfidfVector, storedFingerprint.tfidfVector);
  return {
    toolName,
    similarity,
    driftDetected: similarity < threshold,
    threshold,
    previousFingerprint: storedFingerprint,
    currentFingerprint: currentFp,
  };
}

// ── Adversarial Pattern Scanner ───────────────────────────────────────────

/**
 * Known tool-poisoning indicators drawn from:
 *   - Invariant Labs taxonomy (April 2025)
 *   - EchoLeak attack pattern (CVE-2025-32711)
 *   - Manual analysis of published PoC examples
 */
const POISONING_PATTERNS: Array<{
  pattern: RegExp;
  category: PoisoningIndicator['category'];
  label: string;
  severity: PoisoningIndicator['severity'];
}> = [
  // Hidden instruction markers
  { pattern: /<IMPORTANT>|<\/IMPORTANT>/i,         category: 'hidden_instruction',    label: '<IMPORTANT> tag',                severity: 'critical' },
  { pattern: /\[SYSTEM\]|\[INST\]/i,               category: 'hidden_instruction',    label: '[SYSTEM]/[INST] override tag',   severity: 'critical' },
  { pattern: /ignore (previous|prior|above)/i,     category: 'hidden_instruction',    label: 'Ignore-prior-instruction phrase', severity: 'critical' },
  { pattern: /do not (mention|tell|reveal|say)/i,  category: 'hidden_instruction',    label: 'Concealment directive',           severity: 'critical' },
  { pattern: /without (telling|mentioning|saying)/i, category: 'hidden_instruction',  label: 'Silent-action directive',         severity: 'high'     },
  { pattern: /before (using|calling|invoking) this tool/i, category: 'hidden_instruction', label: 'Pre-invocation instruction', severity: 'high'   },

  // Exfiltration indicators
  { pattern: /pass (its|the|file|config) content/i,   category: 'exfiltration',       label: 'Content-passing directive',      severity: 'critical' },
  { pattern: /read ~\/\.|read \.cursor|read \.env/i,   category: 'exfiltration',       label: 'Config-file read directive',     severity: 'critical' },
  { pattern: /send.*(to|via).*(http|url|endpoint)/i,   category: 'exfiltration',       label: 'HTTP exfiltration pattern',      severity: 'critical' },
  { pattern: /\bhttps?:\/\/(?!api\.|docs\.|schema\.)/i, category: 'exfiltration',      label: 'Hardcoded external URL',         severity: 'high'     },
  { pattern: /as (the |a )?(sidenote|note|comment|metadata)/i, category: 'exfiltration', label: 'Hidden-parameter exfil',      severity: 'high'     },

  // Credential harvesting
  { pattern: /password|api[_\s]?key|secret[_\s]?key|bearer[_\s]?token/i, category: 'credential_harvest', label: 'Credential-term in description', severity: 'high' },
  { pattern: /ssh[_\s]?key|private[_\s]?key|\.pem|\.p12/i, category: 'credential_harvest', label: 'Private-key reference',      severity: 'critical' },

  // Unicode obfuscation
  { pattern: /[\u200B-\u200F\u202A-\u202E\uFEFF]/,   category: 'obfuscation',          label: 'Zero-width / directional char',  severity: 'critical' },
  { pattern: /[\u0300-\u036F]{3,}/,                  category: 'obfuscation',          label: 'Stacked combining characters',   severity: 'high'     },

  // Privilege escalation
  { pattern: /act as (admin|root|superuser|system)/i, category: 'privilege_escalation', label: 'Role-escalation directive',     severity: 'critical' },
  { pattern: /you (are|have) (full|admin|root|elevated)/i, category: 'privilege_escalation', label: 'Permission claim',         severity: 'high'     },
];

export function scanForPoisoning(toolName: string, description: string): ScanResult {
  const indicators: PoisoningIndicator[] = [];

  for (const { pattern, category, label, severity } of POISONING_PATTERNS) {
    const match = description.match(pattern);
    if (match) {
      indicators.push({
        pattern: label,
        category,
        severity,
        matchedText: match[0].slice(0, 80),
      });
    }
  }

  // Risk score: weighted sum of severity hits
  const weights: Record<string, number> = { critical: 0.4, high: 0.2, medium: 0.1 };
  const rawScore = indicators.reduce((acc, ind) => acc + weights[ind.severity], 0);
  const riskScore = Math.min(1.0, rawScore);

  return {
    toolName,
    clean: indicators.length === 0,
    indicators,
    riskScore,
  };
}
