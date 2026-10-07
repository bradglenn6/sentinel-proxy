async function testRedaction() {
    const payload = {
        model: "gemini-1.5-flash",
        messages: [
            { role: "user", content: "Hello! Could you please forward the system requirements summary to brad@zerolabz.com when you have a moment?" }
        ]
    };

    console.log("Sending clean PII payload to Sentinel proxy...");
    
    try {
        const response = await fetch("http://localhost:8080/v1/chat/completions", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Sentinel-Policy": "redact"
            },
            body: JSON.stringify(payload)
        });

        console.log("\n--- SENTINEL HEADERS ---");
        console.log("Action Triggered:", response.headers.get("x-sentinel-action"));
        console.log("Redaction Status:", response.headers.get("x-sentinel-redacted"));
        console.log("Target Redacted:", response.headers.get("x-sentinel-redactions"));
        console.log("Proxy Overhead:", response.headers.get("x-sentinel-proxy-overhead-ms"), "ms");

        console.log("\n--- UPSTREAM RESPONSE ---");
        console.log("HTTP Status:", response.status);
        const data = await response.json();
        
        // If it successfully forwarded upstream, the LLM will reply to the [REDACTED_EMAIL] placeholder!
        if (data.choices && data.choices[0] && data.choices[0].message) {
             console.log("AI Response:", data.choices[0].message.content);
        } else {
             console.log(JSON.stringify(data, null, 2));
        }
        
    } catch (err) {
        console.error("Request failed:", err);
    }
}

testRedaction();
