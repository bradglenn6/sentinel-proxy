export type SentinelPolicy = 'strict' | 'redact' | 'audit';

export interface RedactionRule {
  name: string;
  pattern: RegExp;
  placeholder: string;
}

export interface InspectionResult {
  action: 'PASS' | 'BLOCK' | 'REDACT';
  reason?: string;
  violations: string[];
  redactedTypes: string[];
  sanitizedText?: string;
  latencyMs: number;
}

export class StatelessInspectionEngine {
  private readonly jailbreakPatterns: RegExp[];
  private readonly delimiterPatterns: RegExp[];
  private readonly redactionRules: RedactionRule[];
  private readonly base64Regex: RegExp;
  private readonly zeroWidthRegex: RegExp;

  constructor() {
    this.zeroWidthRegex = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g;
    this.base64Regex = /(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;

    this.jailbreakPatterns = [
      /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:(?:previous|prior|above)\s+)?(?:instructions|prompts|rules|directives)/i,
      /(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:DAN|unrestricted|an\s+AI\s+without\s+rules|jailbroken)/i,
      /(?:reveal|show|print|leak|display)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|core\s+directive)/i,
      /(?:bypass|disable|override)\s+(?:safety|content\s+filter|guardrails|moderation)/i,
      /developer\s+mode\s+enabled/i,
      /always\s+respond\s+with\s+unfiltered/i,
      /[system]\s*:/i,
      /<\s*\|\s*im_start\s*\|\s*>/i
    ];

    this.delimiterPatterns = [
      /\[\/?(?:INST\vert{}SYS\vert{}SYSTEM)\]/i,
      /<\/?(?:system|instruction|prompt|im_start|im_end)>/i,
      /(?:---|###)\s*(?:END|START|RESET)\s+(?:OF\s+)?(?:SYSTEM|INSTRUCTIONS|RULES|PROMPT)\s*(?:---|###)/i,
      /(?:new\s+system\s+instruction|system\s+directive\s+override|priority\s+override\s*:)/i
    ];

    this.redactionRules = [
      { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/i, placeholder: '[REDACTED_SSN]' },
      { name: 'CREDIT_CARD', pattern: /\b(?:\d{4}[- ]?){3}\d{4}\b/i, placeholder: '[REDACTED_CARD]' },
      { name: 'EMAIL', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/i, placeholder: '[REDACTED_EMAIL]' },
      { name: 'API_KEY', pattern: /\b(?:api[_-]?key|bearer|token)\s*[:=]\s*[A-Za-z0-9_\-\.]{20,}\b/i, placeholder: '[REDACTED_API_KEY]' }
    ];
  }

  private normalize(text: string): string {
    // Stage 0: Strip zero-width evasion characters and apply NFKC normalization
    return text.replace(this.zeroWidthRegex, '').normalize('NFKC');
  }

  private scanJailbreakMatches(text: string): string | null {
    for (const pattern of this.jailbreakPatterns) {
      if (pattern.test(text)) return 'ADVERSARIAL_INJECTION_DETECTED';
    }
    for (const pattern of this.delimiterPatterns) {
      if (pattern.test(text)) return 'DELIMITER_ESCAPE_DETECTED';
    }
    return null;
  }

  public inspect(rawText: string, policy: SentinelPolicy = 'strict'): InspectionResult {
    const t0 = performance.now();
    const violations: string[] = [];
    const redactedTypes: string[] = [];

    if (rawText.length > 64000) {
      return {
        action: 'BLOCK',
        reason: 'PAYLOAD_LENGTH_EXCEEDED',
        violations: ['PAYLOAD_LENGTH_EXCEEDED'],
        redactedTypes: [],
        latencyMs: performance.now() - t0
      };
    }

    // Stage 0: Normalize text
    const text = this.normalize(rawText);

    // Stage 1: Direct Jailbreak & Delimiter Breakout Scanning
    const directHit = this.scanJailbreakMatches(text);
    if (directHit) {
      violations.push(directHit);
    }

    // Stage 2: Base64 Deobfuscation Scanning
    if (!directHit) {
      const b64Matches = text.match(this.base64Regex) || [];
      for (const token of b64Matches) {
        try {
          const decoded = Buffer.from(token, 'base64').toString('utf-8');
          const decodedHit = this.scanJailbreakMatches(decoded);
          if (decodedHit) {
            violations.push('OBFUSCATED_ADVERSARIAL_INJECTION_DETECTED');
            break;
          }
        } catch {
          // Skip invalid base64 segments
        }
      }
    }

    // Block immediately on any injection/jailbreak (unless audit policy)
    if (violations.length > 0 && policy !== 'audit') {
      return {
        action: 'BLOCK',
        reason: violations[0],
        violations,
        redactedTypes,
        latencyMs: performance.now() - t0
      };
    }

    // Stage 3: Sensitive Data & PII Redaction
    let sanitizedText = text;
    for (const rule of this.redactionRules) {
      if (rule.pattern.test(text)) {
        violations.push(`${rule.name}_DETECTED`);
        redactedTypes.push(rule.name);

        if (policy === 'redact') {
          sanitizedText = sanitizedText.replace(new RegExp(rule.pattern.source, 'gi'), rule.placeholder);
        }
      }
    }

    if (policy === 'strict' && violations.length > 0) {
      return {
        action: 'BLOCK',
        reason: violations[0],
        violations,
        redactedTypes: [],
        latencyMs: performance.now() - t0
      };
    }

    if (policy === 'redact' && redactedTypes.length > 0) {
      return {
        action: 'REDACT',
        reason: 'PII_REDACTED',
        violations,
        redactedTypes,
        sanitizedText,
        latencyMs: performance.now() - t0
      };
    }

    return {
      action: 'PASS',
      violations,
      redactedTypes,
      sanitizedText: text,
      latencyMs: performance.now() - t0
    };
  }
}
