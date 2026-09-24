export interface SecurityAuditEvent {
  severity: 'INFO' | 'WARNING' | 'ERROR';
  message: string;
  event: 'guardrail_blocked' | 'guardrail_redacted' | 'guardrail_audit_flagged' | 'guardrail_pass';
  policy: string;
  action: 'PASS' | 'BLOCK' | 'REDACT';
  violations: string[];
  redactedTypes: string[];
  latencyMs: number;
  model?: string;
  clientIp?: string;
  traceId?: string;
}

export class AuditLogger {
  public static logEvent(event: SecurityAuditEvent): void {
    const payload = {
      ...event,
      timestamp: new Date().toISOString(),
      service: 'zerolabz-sentinel',
      'logging.googleapis.com/trace': event.traceId
    };

    // Non-blocking write to stdout for Cloud Run automatic log parsing
    process.stdout.write(JSON.stringify(payload) + '\n');
  }
}
