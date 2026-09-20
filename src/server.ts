import { DASHBOARD_HTML } from './dashboard';
import fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { request } from 'undici';
import { Transform, TransformCallback } from 'stream';
import { StatelessInspectionEngine } from './engine';

const app: FastifyInstance = fastify({ logger: false });
const engine = new StatelessInspectionEngine();

const UPSTREAM_LLM_URL = process.env.UPSTREAM_LLM_URL || 'https://generativelanguage.googleapis.com';

interface ChatMessage {
  role: string;
  content: string;
}

interface ChatCompletionBody {
  model?: string;
  messages?: ChatMessage[];
  stream?: boolean;
}

// -------------------------------------------------------------
// Root & Health Landing Page (Browser-friendly)
// -------------------------------------------------------------
const renderStatusHtml = () => `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ZeroLabz Sentinel — Active</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0B0F17; color: #E2E8F0; margin: 0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #151E2E; border: 1px solid #264669; border-radius: 12px; padding: 40px; max-width: 520px; width: 90%; box-shadow: 0 10px 30px rgba(0,0,0,0.5); text-align: center; }
    h1 { color: #38BDF8; font-size: 26px; margin: 0 0 10px; font-weight: 700; letter-spacing: -0.5px; }
    .status-badge { display: inline-block; background: rgba(16, 185, 129, 0.2); border: 1px solid #10B981; color: #34D399; font-size: 12px; font-weight: 700; letter-spacing: 0.5px; padding: 5px 14px; border-radius: 9999px; margin-bottom: 24px; text-transform: uppercase; }
    p { color: #94A3B8; font-size: 15px; line-height: 1.6; margin: 0 0 20px; }
    .endpoints { background: #0B0F17; border: 1px solid #1E293B; border-radius: 8px; padding: 16px; text-align: left; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 13px; color: #CBD5E1; }
    .endpoint-item { margin-bottom: 8px; display: flex; justify-content: space-between; }
    .endpoint-item:last-child { margin-bottom: 0; }
    .method { color: #38BDF8; font-weight: bold; }
    .path { color: #E2E8F0; }
    .desc { color: #64748B; font-size: 12px; }
    .footer { margin-top: 24px; font-size: 13px; color: #64748B; }
    .footer a { color: #38BDF8; text-decoration: none; }
  </style>
</head>
<body>
  <div class="card">
    <h1>ZeroLabz Sentinel</h1>
    <div class="status-badge">? Engine Operational</div>
    <p>Sub-millisecond stateless AI guardrail reverse proxy and inference security gateway.</p>
    <div class="endpoints">
      <div class="endpoint-item">
        <span><span class="method">POST</span> <span class="path">/v1/chat/completions</span></span>
        <span class="desc">Inference Gateway</span>
      </div>
      <div class="endpoint-item">
        <span><span class="method">GET</span> <span class="path">/v1/healthz</span></span>
        <span class="desc">Health Probe</span>
      </div>
    </div>
    <div class="footer">
      Zero-Trust Infrastructure · <a href="https://github.com/bradglenn6/sentinel-proxy" target="_blank">GitHub</a>
    </div>
  </div>
</body>
</html>
`;

app.get('/healthz', async (_req, reply) => {
  return reply.code(200).send({ status: 'ok', engine: 'stateless-v1' });
});

// Root landing dashboard
app.get('/', async (_req, reply) => {
  reply.type('text/html').send(DASHBOARD_HTML);
});

// /v1 with Content Negotiation
app.get('/v1', async (req, reply) => {
  const accept = req.headers['accept'] || '';
  if (typeof accept === 'string' && accept.includes('text/html')) {
    reply.type('text/html').send(DASHBOARD_HTML);
  } else {
    reply.send({
      status: 'ok',
      service: 'ZeroLabz Sentinel',
      version: 'v0.1.1-alpha',
      engine: 'stateless-v1'
    });
  }
});

app.get('/v1/healthz', async (_req, reply) => {
  return reply.code(200).send({ status: 'ok', engine: 'stateless-v1' });
});

/**
 * Sliding-Window Stream Interceptor
 */
class StreamingGuardrailInterceptor extends Transform {
  private windowBuffer: string = '';
  private readonly windowSize: number = 512;
  private isTerminated: boolean = false;

  constructor() {
    super();
  }

  _transform(chunk: Buffer, _encoding: string, callback: TransformCallback): void {
    if (this.isTerminated) {
      return callback();
    }

    const chunkStr = chunk.toString('utf-8');
    this.windowBuffer += chunkStr;
    if (this.windowBuffer.length > this.windowSize * 2) {
      this.windowBuffer = this.windowBuffer.slice(-this.windowSize);
    }

    const inspection = engine.inspect(this.windowBuffer);

    if (inspection.action === 'BLOCK') {
      this.isTerminated = true;
      const errorPayload = {
        error: {
          message: `Streaming terminated by ZeroLabz Sentinel: ${inspection.reason}`,
          type: 'guardrail_stream_violation',
          code: 400
        }
      };

      this.push(`data: ${JSON.stringify(errorPayload)}\n\n`);
      this.push('data: [DONE]\n\n');
      this.destroy();
      return callback();
    }

    this.push(chunk);
    callback();
  }
}

app.post('/v1/chat/completions', async (req: FastifyRequest<{ Body: ChatCompletionBody }>, reply: FastifyReply) => {
  const tStart = performance.now();
  const body = req.body;

  const combinedText = body?.messages?.map(m => m.content).join('\n') || '';
  const inspection = engine.inspect(combinedText);

  if (inspection.action === 'BLOCK') {
    const preDispatchOverhead = performance.now() - tStart;
    return reply.code(400).send({
      error: {
        message: `Blocked by ZeroLabz Sentinel: ${inspection.reason}`,
        type: 'guardrail_violation',
        code: 400,
        latency_overhead_ms: preDispatchOverhead
      }
    });
  }

  const preDispatchOverhead = performance.now() - tStart;

  try {
    const authHeader = req.headers['authorization'];
    const isStreaming = Boolean(body?.stream);

    const upstreamRes = await request(`${UPSTREAM_LLM_URL}/v1/chat/completions`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(authHeader ? { authorization: authHeader as string } : {})
      },
      body: JSON.stringify(body)
    });

    reply.header('X-Sentinel-Inspection-Ms', inspection.latencyMs.toFixed(3));
    reply.header('X-Sentinel-Proxy-Overhead-Ms', preDispatchOverhead.toFixed(3));

    if (isStreaming) {
      reply.header('Content-Type', 'text/event-stream');
      reply.header('Cache-Control', 'no-cache');
      reply.header('Connection', 'keep-alive');

      const interceptor = new StreamingGuardrailInterceptor();
      return reply.code(upstreamRes.statusCode).send(upstreamRes.body.pipe(interceptor));
    } else {
      return reply.code(upstreamRes.statusCode).send(await upstreamRes.body.json());
    }

  } catch (err: any) {
    return reply.code(502).send({
      error: {
        message: 'Upstream gateway error',
        details: err.message
      }
    });
  }
});

const PORT = parseInt(process.env.PORT || '8080', 10);
app.listen({ port: PORT, host: '0.0.0.0' }, (err, address) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  console.log(`[Sentinel] Proxy running on ${address}`);
});
