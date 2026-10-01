export interface SentinelClientOptions {
  baseUrl?: string;
  apiKey?: string;
  policy?: 'strict' | 'redact' | 'audit';
}

export interface OpenAIClientConfig {
  baseURL: string;
  apiKey: string;
  defaultHeaders: Record<string, string>;
}

export interface GeminiClientConfig {
  endpoint: string;
  headers: Record<string, string>;
}

export class SentinelClient {
  public readonly baseUrl: string;
  public readonly apiKey: string;
  public readonly policy: 'strict' | 'redact' | 'audit';

  constructor(options: SentinelClientOptions = {}) {
    this.baseUrl = (
      options.baseUrl ||
      'https://sentinel-proxy-798917645637.us-west2.run.app/v1'
    ).replace(/\/+$/, '');
    this.apiKey = options.apiKey || 'sentinel-stateless';
    this.policy = options.policy || 'strict';
  }

  private getRootUrl(): string {
    return this.baseUrl.endsWith('/v1') ? this.baseUrl.slice(0, -3) : this.baseUrl;
  }

  public async health(): Promise<{ status: string; engine: string; version: string }> {
    const res = await fetch(`${this.getRootUrl()}/v1/healthz`, {
      headers: { 'X-Sentinel-Client': '@zerolabz/sentinel-sdk@1.1.0' },
    });
    if (!res.ok) {
      throw new Error(`Sentinel health check failed with HTTP ${res.status}`);
    }
    return (await res.json()) as { status: string; engine: string; version: string };
  }

  public getOpenAIConfig(): OpenAIClientConfig {
    return {
      baseURL: this.baseUrl,
      apiKey: this.apiKey,
      defaultHeaders: {
        'X-Sentinel-Client': '@zerolabz/sentinel-sdk@1.1.0',
        'X-Sentinel-Policy': this.policy,
      },
    };
  }

  public getGeminiConfig(): GeminiClientConfig {
    return {
      endpoint: `${this.getRootUrl()}/v1/chat/completions`,
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        'X-Sentinel-Client': '@zerolabz/sentinel-sdk@1.1.0',
        'X-Sentinel-Policy': this.policy,
        'Content-Type': 'application/json',
      },
    };
  }

  // --- Xero Runtime Recovery & SIEM APIs ---

  public async getMesh(): Promise<any> {
    const res = await fetch(`${this.getRootUrl()}/api/mesh`);
    return await res.json();
  }

  public async evaluateTelemetry(telemetry: {
    agent_id: string;
    drift_score: number;
    token_velocity?: number;
    cpu_usage?: number;
    memory_mb?: number;
    unauthorized_calls?: number;
  }): Promise<any> {
    const res = await fetch(`${this.getRootUrl()}/api/telemetry/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token_velocity: 35,
        cpu_usage: 25.0,
        memory_mb: 256,
        unauthorized_calls: 0,
        ...telemetry,
      }),
    });
    return await res.json();
  }

  public async triggerRecovery(agentId: string): Promise<any> {
    const res = await fetch(`${this.getRootUrl()}/api/recovery/trigger`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent_id: agentId }),
    });
    return await res.json();
  }

  public async getSiemLogs(): Promise<any> {
    const res = await fetch(`${this.getRootUrl()}/api/siem/logs`);
    return await res.json();
  }
}
