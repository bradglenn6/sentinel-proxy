import fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { request } from 'undici';
import { Transform, TransformCallback } from 'stream';
import { StatelessInspectionEngine } from './engine';

const app: FastifyInstance = fastify({ logger: false });
const engine = new StatelessInspectionEngine();

const UPSTREAM_LLM_URL = 'https://generativelanguage.googleapis.com/v1beta/openai';
const GEMINI_KEY = process.env.GEMINI_KEY || '';

interface ChatMessage {
  role: string;
  content: string;
}

interface ChatCompletionBody {
  model?: string;
  messages?: ChatMessage[];
  stream?: boolean;
}

app.get('/healthz', async (_req, reply) => reply.send({ status: 'ok', engine: 'stateless-v1' }));
app.get('/v1/healthz', async (_req, reply) => {
  return reply.code(200).send({ status: 'ok', engine: 'stateless-v1' });
});

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
    const isStreaming = Boolean(body?.stream);
    const requestedModel = (body.model && !body.model.includes('2.5')) ? body.model : 'gemini-3.6-flash';

    const upstreamRes = await request(`${UPSTREAM_LLM_URL}/chat/completions?key=${GEMINI_KEY}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-goog-api-key': GEMINI_KEY,
        'authorization': `Bearer ${GEMINI_KEY}`
      },
      body: JSON.stringify({
        model: requestedModel,
        messages: body.messages,
        stream: isStreaming
      })
    });

    reply.header('X-Sentinel-Inspection-Ms', inspection.latencyMs.toFixed(3));
    reply.header('X-Sentinel-Proxy-Overhead-Ms', preDispatchOverhead.toFixed(3));

    if (isStreaming) {
      reply.header('Content-Type', 'text/event-stream');
      reply.header('Cache-Control', 'no-cache');
      reply.header('Connection', 'keep-alive');
      const interceptor = new StreamingGuardrailInterceptor();
      return reply.code(upstreamRes.statusCode).send((upstreamRes.body as any).pipe(interceptor));
    } else {
      const rawText = await upstreamRes.body.text();
      let data;
      try {
        data = JSON.parse(rawText);
      } catch {
        data = { raw_upstream: rawText };
      }
      return reply.code(upstreamRes.statusCode).send(data);
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
