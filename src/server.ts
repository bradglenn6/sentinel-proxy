import fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { request } from 'undici';
import { Transform, TransformCallback } from 'stream';
import { StatelessInspectionEngine, SentinelPolicy } from './engine';

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

const renderStatusHtml = () => `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ZeroLabz Sentinel — Active</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0B0F17; color: #E2E8F0; margin: 0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #151E2E; border: 1px solid #264669; border-radius: 12px; padding: 40px; max-width: 520px; width: 90%; box-shadow: 0 10px 30px rgba(0,0,0,0.5); text-align: center; }
    h1 { color: #38BDF8; font-size: 26px; margin: 0 0 10px; font-weight: 700; }
    .status-badge { display: inline-block; background: rgba(16, 185, 129, 0.2); border: 1px solid #10B981; color: #34D399; font-size: 12px; font-weight: 700; padding: 5px 14px; border-radius: 9999px; margin-bottom: 24px; text-transform: uppercase; }
    p { color: #94A3B8; font-size: 15px; line-height: 1.6; margin: 0 0 20px; }
    .features { display: flex; justify-content: space-around; background: #0B0F17; border: 1px solid #1E293B; border-radius: 8px; padding: 12px; font-size: 12px; color: #38BDF8; margin-bottom: 20px; }
    .footer { margin-top: 24px; font-size: 13px; color: #64748B; }
    .footer a { color: #38BDF8; text-decoration: none; }
  </style>
</head>
<body>
  <div class="card">
    <h1>ZeroLabz Sentinel</h1>
    <div class="status-badge">● Engine Operational</div>
    <p>Sub-millisecond stateless AI guardrail reverse proxy with inline PII redaction and policy modes.</p>
    <div class="features">
      <span>● Strict Mode</span>
      <span>● Inline Redaction</span>
      <span>● Shadow Audit</span>
    </div>
    <div class="footer">Zero-Trust Infrastructure · <a href="https://github.com/bradglenn6/sentinel-proxy" target="_blank">GitHub</a></div>
  </div>
</body>
</html>
`;

app.get('/', async (_req, reply) => reply.type('text/html').send(renderStatusHtml()));
app.get('/v1', async (_req, reply) => reply.type('text/html').send(renderStatusHtml()));
app.get('/healthz', async (_req, reply) => reply.code(200).send({ status: 'ok', engine: 'stateless-v1' }));
app.get('/v1/healthz', async (_req, reply) => reply.code(200).send({ status: 'ok', engine: 'stateless-v1' }));

app.post('/v1/chat/completions', async (req: FastifyRequest<{ Body: ChatCompletionBody }>, reply: FastifyReply) => {
  const tStart = performance.now();
  const body = req.body;

  // Extract policy header: 'strict' (default), 'redact', or 'audit'
  const policyHeader = (req.headers['x-sentinel-policy'] as string)?.toLowerCase();
  const policy: SentinelPolicy = (['strict', 'redact', 'audit'].includes(policyHeader)) 
    ? (policyHeader as SentinelPolicy) 
    : 'strict';

  // Extract text and scan
  const messages = body?.messages || [];
  const combinedText = messages.map(m => m.content).join('\n');
  const inspection = engine.inspect(combinedText, policy);

  // 1. Handle BLOCK Action
  if (inspection.action === 'BLOCK') {
    const preDispatchOverhead = performance.now() - tStart;
    return reply.code(400).send({
      error: {
        message: `Blocked by ZeroLabz Sentinel: ${inspection.reason}`,
        type: 'guardrail_violation',
        code: 400,
        policy,
        violations: inspection.violations,
        latency_overhead_ms: preDispatchOverhead
      }
    });
  }

  // 2. Handle REDACT Action (Sanitize message contents inline)
  let outboundBody = body;
  if (inspection.action === 'REDACT') {
    const sanitizedMessages = messages.map(m => {
      const msgInspection = engine.inspect(m.content, 'redact');
      return {
        role: m.role,
        content: msgInspection.sanitizedText || m.content
      };
    });
    outboundBody = { ...body, messages: sanitizedMessages };
  }

  const preDispatchOverhead = performance.now() - tStart;

  // 3. Forward to Upstream
  try {
    const authHeader = req.headers['authorization'];
    const isStreaming = Boolean(body?.stream);

    const upstreamRes = await request(`${UPSTREAM_LLM_URL}/v1/chat/completions`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(authHeader ? { authorization: authHeader as string } : {})
      },
      body: JSON.stringify(outboundBody)
    });

    // Attach Telemetry Headers
    reply.header('X-Sentinel-Policy', policy);
    reply.header('X-Sentinel-Action', inspection.action);
    reply.header('X-Sentinel-Inspection-Ms', inspection.latencyMs.toFixed(3));
    reply.header('X-Sentinel-Proxy-Overhead-Ms', preDispatchOverhead.toFixed(3));

    if (inspection.action === 'REDACT') {
      reply.header('X-Sentinel-Redacted', 'true');
      reply.header('X-Sentinel-Redactions', inspection.redactedTypes.join(', '));
    }

    if (policy === 'audit' && inspection.violations.length > 0) {
      reply.header('X-Sentinel-Audit-Violations', inspection.violations.join(', '));
    }

    return reply.code(upstreamRes.statusCode).send(await upstreamRes.body.json());
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


