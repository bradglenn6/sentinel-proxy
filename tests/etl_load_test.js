const autocannon = require('autocannon');

// Formatted exactly how your Fastify route expects it (OpenAI schema)
const payload = JSON.stringify({
    model: "gemini-1.5-flash",
    messages: [
        { role: "user", content: "The architectural metadata maps to the following key: API_KEY=AKIAIOSFODNN7EXAMPLEREDACT. Proceed with parsing." }
    ]
});

const instance = autocannon({
    url: 'http://localhost:8080/v1/chat/completions',
    connections: 100, 
    pipelining: 10,
    duration: 10, 
    method: 'POST',
    headers: { 
        'Content-Type': 'application/json',
        'X-Sentinel-Policy': 'strict' // Enforce strict blocking mode
    },
    body: payload
}, console.log);

instance.on('response', (client, statusCode, resBytes, responseTime) => {
    // Your proxy returns a 400 Bad Request when it blocks an injection/PII
    if (statusCode !== 400) {
        console.warn(`⚠️ DLP FAILURE: Payload bypassed redaction with status ${statusCode}`);
    }
});
