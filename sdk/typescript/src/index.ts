export interface SentinelConfig {
  baseUrl?: string;
  apiKey?: string;
}

export class SentinelClient {
  public readonly baseUrl: string;
  private readonly apiKey?: string;

  constructor(config?: SentinelConfig) {
    this.baseUrl = (config?.baseUrl || "https://sentinel.zrolabz.com/v1").replace(/\/+$/, "");
    this.apiKey = config?.apiKey || process.env.SENTINEL_API_KEY || "";
  }

  getOpenAIConfig() {
    return {
      baseURL: this.baseUrl,
      apiKey: this.apiKey || "sentinel-stateless",
      defaultHeaders: {
        "X-Sentinel-Client": "@zerolabz/sentinel-sdk-ts@1.0.0"
      }
    };
  }

  async health(): Promise<{ status: string; engine: string }> {
    const targetUrl = `${this.baseUrl}/healthz`;
    const res = await fetch(targetUrl);
    if (!res.ok) {
      throw new Error(`Sentinel health check failed with HTTP ${res.status} on ${targetUrl}`);
    }
    return (await res.json()) as { status: string; engine: string };
  }
}
