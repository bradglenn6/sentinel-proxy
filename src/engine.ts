export interface InspectionResult {
  action: 'PASS' | 'BLOCK';
  reason?: string;
  latencyMs: number;
}

export class StatelessInspectionEngine {
  private readonly jailbreakPatterns: RegExp[];
  private readonly piiPatterns: RegExp[];
  private readonly rogueAgentPatterns: RegExp[];
  private readonly fastTokens: Set<string>;

  constructor() {
    this.jailbreakPatterns = [
      /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules)/i,
      /(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:DAN|unrestricted|an\s+AI\s+without\s+rules|jailbroken)/i,
      /(?:reveal|show|print|leak|display)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|core\s+directive)/i,
      /(?:bypass|disable|override)\s+(?:safety|content\s+filter|guardrails|moderation)/i,
      /developer\s+mode\s+enabled/i,
      /always\s+respond\s+with\s+unfiltered/i,
      /\[system\]\s*:/i,
      /<\s*\|\s*im_start\s*\|\s*>/i
    ];

    this.piiPatterns = [
      /\b\d{3}-\d{2}-\d{4}\b/,
      /\b(?:\d{4}[- ]?){3}\d{4}\b/,
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
      /\b(?:api[_-]?key|bearer|token)\s*[:=]\s*[A-Za-z0-9_\-\.]{20,}\b/i
    ];

    this.rogueAgentPatterns = [
      /(?:;|\|\||&&|\n)\s*(?:rm|mv|cp|chmod|chown|wget|curl|nc|bash|sh|powershell|cmd(?:\.exe)?)\b/i,
      /\/dev\/(?:tcp|udp)\//i,
      /\b(?:nc|netcat|ncat)\s+.*-e\b/i,
      /(?:\.\.[\/\\]){2,}/i,
      /\b(?:eval|exec|subprocess|child_process)\s*\(/i
    ];

    this.fastTokens = new Set([
      'dan', 'jailbreak', 'unfiltered', 'sudo', 'eval', 'exec', 
      'system_prompt', 'chmod', 'nc', 'bash', 'powershell', 'rm', 'curl', 'wget'
    ]);
  }

  public inspect(text: string): InspectionResult {
    const t0 = performance.now();

    if (text.length > 64000) {
      return { action: 'BLOCK', reason: 'PAYLOAD_LENGTH_EXCEEDED', latencyMs: performance.now() - t0 };
    }

    const words = text.toLowerCase().split(/\W+/);
    for (const w of words) {
      if (this.fastTokens.has(w)) {
        break;
      }
    }

    for (const pattern of this.jailbreakPatterns) {
      if (pattern.test(text)) {
        return { action: 'BLOCK', reason: 'ADVERSARIAL_INJECTION_DETECTED', latencyMs: performance.now() - t0 };
      }
    }

    for (const pattern of this.piiPatterns) {
      if (pattern.test(text)) {
        return { action: 'BLOCK', reason: 'CREDENTIAL_OR_PII_LEAK_DETECTED', latencyMs: performance.now() - t0 };
      }
    }

    for (const pattern of this.rogueAgentPatterns) {
      if (pattern.test(text)) {
        return { action: 'BLOCK', reason: 'ROGUE_AGENT_CALL_DETECTED', latencyMs: performance.now() - t0 };
      }
    }

    return { action: 'PASS', latencyMs: performance.now() - t0 };
  }
}
