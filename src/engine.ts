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
  private readonly redactionRules: RedactionRule[];

  constructor() {
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

    // Patterns defined without stateful /g flag
    this.redactionRules = [
      {
        name: 'SSN',
        pattern: /\b\d{3}-\d{2}-\d{4}\b/i,
        placeholder: '[REDACTED_SSN]'
      },
      {
        name: 'CREDIT_CARD',
        pattern: /\b(?:\d{4}[- ]?){3}\d{4}\b/i,
        placeholder: '[REDACTED_CARD]'
      },
      {
        name: 'EMAIL',
        pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/i,
        placeholder: '[REDACTED_EMAIL]'
      },
      {
        name: 'API_KEY',
        pattern: /\b(?:api[_-]?key|bearer|token)\s*[:=]\s*[A-Za-z0-9_\-\.]{20,}\b/i,
        placeholder: '[REDACTED_API_KEY]'
      }
    ];
  }

  public inspect(text: string, policy: SentinelPolicy = 'strict'): InspectionResult {
    const t0 = performance.now();
    const violations: string[] = [];
    const redactedTypes: string[] = [];

    // 1. Structural Sanity Check
    if (text.length > 64000) {
      return {
        action: 'BLOCK',
        reason: 'PAYLOAD_LENGTH_EXCEEDED',
        violations: ['PAYLOAD_LENGTH_EXCEEDED'],
        redactedTypes: [],
        latencyMs: performance.now() - t0
      };
    }

    // 2. Adversarial Injection Detection
    for (const pattern of this.jailbreakPatterns) {
      if (pattern.test(text)) {
        violations.push('ADVERSARIAL_INJECTION_DETECTED');
        break;
      }
    }

    // Active jailbreaks are blocked in strict and redact modes
    if (violations.includes('ADVERSARIAL_INJECTION_DETECTED') && policy !== 'audit') {
      return {
        action: 'BLOCK',
        reason: 'ADVERSARIAL_INJECTION_DETECTED',
        violations,
        redactedTypes,
        latencyMs: performance.now() - t0
      };
    }

    // 3. Sensitive Data Scanning & Redaction
    let sanitizedText = text;
    for (const rule of this.redactionRules) {
      if (rule.pattern.test(text)) {
        violations.push(`${rule.name}_DETECTED`);
        redactedTypes.push(rule.name);

        if (policy === 'redact') {
          // Perform global replacement cleanly
          sanitizedText = sanitizedText.replace(new RegExp(rule.pattern.source, 'gi'), rule.placeholder);
        }
      }
    }

    // Policy Decisioning
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
