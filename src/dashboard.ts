export const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ZeroLabz Sentinel | AI Guardrail Reverse Proxy</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --border: #1f2937;
      --text: #f3f4f6;
      --muted: #9ca3af;
      --accent: #10b981;
      --accent-glow: rgba(16, 185, 129, 0.2);
      --code-bg: #030712;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background-color: var(--bg); color: var(--text); padding: 2rem 1rem; display: flex; justify-content: center; }
    .container { max-width: 800px; width: 100%; }
    header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; }
    .logo { font-size: 1.25rem; font-weight: 700; letter-spacing: -0.025em; }
    .logo span { color: var(--accent); }
    .badge { display: flex; align-items: center; gap: 0.5rem; font-size: 0.875rem; background: var(--accent-glow); color: var(--accent); padding: 0.25rem 0.75rem; border-radius: 9999px; border: 1px solid rgba(16, 185, 129, 0.4); }
    .dot { width: 8px; height: 8px; background: var(--accent); border-radius: 50%; box-shadow: 0 0 8px var(--accent); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }
    .card-label { font-size: 0.75rem; text-transform: uppercase; color: var(--muted); font-weight: 600; margin-bottom: 0.5rem; }
    .card-val { font-size: 1.5rem; font-weight: 700; color: #fff; }
    .card-sub { font-size: 0.75rem; color: var(--accent); margin-top: 0.25rem; }
    .section-title { font-size: 1rem; font-weight: 600; margin-bottom: 0.75rem; }
    pre { background: var(--code-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; overflow-x: auto; font-family: monospace; font-size: 0.875rem; color: #e5e7eb; margin-bottom: 2rem; }
    footer { display: flex; justify-content: space-between; font-size: 0.875rem; color: var(--muted); border-top: 1px solid var(--border); padding-top: 1.5rem; }
    a { color: #60a5fa; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">ZeroLabz <span>Sentinel</span></div>
      <div class="badge"><div class="dot"></div> Engine Active</div>
    </header>
    <div class="grid">
      <div class="card">
        <div class="card-label">Core Engine Latency</div>
        <div class="card-val">28 µs</div>
        <div class="card-sub">&lt; 0.04 ms HTTP 400 Intercept</div>
      </div>
      <div class="card">
        <div class="card-label">Cloud Edge Loop</div>
        <div class="card-val">0.29 ms</div>
        <div class="card-sub">SLA Target &le; 4.0 ms (Pass)</div>
      </div>
      <div class="card">
        <div class="card-label">Verified Throughput</div>
        <div class="card-val">19,209/s</div>
        <div class="card-sub">Stateless O(1) + DFA Scanning</div>
      </div>
    </div>
    <div class="section-title">Drop-in Integration (OpenAI & Gemini Compatible)</div>
    <pre><code>import OpenAI from 'openai';

const client = new OpenAI({
  apiKey: process.env.MODEL_API_KEY,
  baseURL: 'https://sentinel-proxy-ssqdynq7cq-wl.a.run.app/v1' // Routed through Sentinel
});

const response = await client.chat.completions.create({
  model: 'gemini-2.5-flash',
  messages: [{ role: 'user', content: 'Safe real-time inference' }]
});</code></pre>
    <footer>
      <div>Version: v0.1.1-alpha | ZeroLabz R&amp;D</div>
      <div>
        <a href="https://github.com/bradglenn6/sentinel-proxy" target="_blank">GitHub</a> &bull;
        <a href="/healthz">Health Probe</a>
      </div>
    </footer>
  </div>
</body>
</html>`;
