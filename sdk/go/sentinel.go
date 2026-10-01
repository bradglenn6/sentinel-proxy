package sentinel

import (
"bytes"
"encoding/json"
"fmt"
"net/http"
"strings"
"time"
)

type Client struct {
BaseURL    string
APIKey     string
Policy     string
HTTPClient *http.Client
}

func NewClient(baseURL, apiKey, policy string) *Client {
if baseURL == "" {
baseURL = "https://sentinel-proxy-798917645637.us-west2.run.app/v1"
}
if apiKey == "" {
apiKey = "sentinel-stateless"
}
if policy == "" {
policy = "strict"
}
return &Client{
BaseURL:    strings.TrimRight(baseURL, "/"),
APIKey:     apiKey,
Policy:     strings.ToLower(policy),
HTTPClient: &http.Client{Timeout: 10 * time.Second},
}
}

func (c *Client) rootURL() string {
if strings.HasSuffix(c.BaseURL, "/v1") {
return strings.TrimSuffix(c.BaseURL, "/v1")
}
return c.BaseURL
}

func (c *Client) Health() (map[string]interface{}, error) {
req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/healthz", c.rootURL()), nil)
if err != nil {
return nil, err
}
req.Header.Set("X-Sentinel-Client", "zerolabz-sentinel-go@1.1.0")

resp, err := c.HTTPClient.Do(req)
if err != nil {
return nil, err
}
defer resp.Body.Close()

var result map[string]interface{}
if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
return nil, err
}
return result, nil
}

func (c *Client) TriggerRecovery(agentID string) (map[string]interface{}, error) {
body, _ := json.Marshal(map[string]string{"agent_id": agentID})
req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/recovery/trigger", c.rootURL()), bytes.NewBuffer(body))
if err != nil {
return nil, err
}
req.Header.Set("Content-Type", "application/json")

resp, err := c.HTTPClient.Do(req)
if err != nil {
return nil, err
}
defer resp.Body.Close()

var result map[string]interface{}
if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
return nil, err
}
return result, nil
}
