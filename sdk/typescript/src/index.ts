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

export class SentinelClient {
  public readonly baseUrl: string;
  public readonly apiKey: string;
  public readonly policy: 'strict' | 'redact' | 'audit';

  constructor(options: SentinelClientOptions = {}) {
    this.baseUrl = (options.baseUrl || 'https://sentinel.zrolabz.com/v1').replace(/\/+$/, '');
    this.apiKey = options.apiKey || 'sentinel-stateless';
    this.policy = options.policy || 'strict';
  }

  public async health(): Promise<{ status: string; engine: string }> {
    const rootUrl = this.baseUrl.endsWith('/v1') 
      ? this.baseUrl.slice(0, -3) 
      : this.baseUrl;

    const res = await fetch(`${rootUrl}/v1/healthz`, {
      headers: { 'X-Sentinel-Client': '@zerolabz/sentinel-sdk@1.0.0' }
    });

    if (!res.ok) {
      throw new Error(`Sentinel health check failed with HTTP ${res.status}`);
    }

    return (await res.json()) as { status: string; engine: string };
  }

  public getOpenAIConfig(): OpenAIClientConfig {
    return {
      baseURL: this.baseUrl,
      apiKey: this.apiKey,
      defaultHeaders: {
        'X-Sentinel-Client': '@zerolabz/sentinel-sdk@1.0.0',
        'X-Sentinel-Policy': this.policy
      }
    };
  }
}
