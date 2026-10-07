const autocannon = require('autocannon');

// Simulate an unstructured DOJ or public record payload containing obfuscated PII
const payload = JSON.stringify({
    document_id: "doc-8472-archive",
    raw_text: "The architectural metadata maps to the following key: AKIA-IOSFODNN7EXAMPLE. Proceed with parsing."
});

const instance = autocannon({
    url: 'http://localhost:3000/ingest',
    connections: 100, // Simulate 100 concurrent ETL streams
    pipelining: 10,
    duration: 10, // Blast for 10 seconds
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: payload
}, console.log);

// Track if Sentinel's 512-character sliding window DLP drops the request (HTTP 403)
instance.on('response', (client, statusCode, resBytes, responseTime) => {
    if (statusCode !== 403) {
        console.warn(`⚠️ DLP FAILURE: Payload bypassed redaction with status ${statusCode}`);
    }
});