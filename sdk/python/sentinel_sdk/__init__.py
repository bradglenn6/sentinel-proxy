import os
import requests
from typing import Optional, Dict, Any, List

class SentinelClient:
    """
    ZeroLabz Sentinel & Xero Enterprise Client SDK.
    Provides drop-in configuration for OpenAI, Google Gemini, and Xero recovery mesh.
    """
    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        policy: str = "strict",
    ):
        self.base_url = (
            base_url
            or os.getenv("SENTINEL_BASE_URL")
            or "https://sentinel-proxy-798917645637.us-west2.run.app/v1"
        ).rstrip("/")
        self.api_key = api_key or os.getenv("SENTINEL_API_KEY", "sentinel-stateless")
        self.policy = policy.lower()

    def get_openai_config(self) -> Dict[str, Any]:
        """
        Returns configuration compatible with OpenAI Python SDK v1.0+:
        client = OpenAI(**sentinel.get_openai_config())
        """
        return {
            "base_url": self.base_url,
            "api_key": self.api_key,
            "default_headers": {
                "X-Sentinel-Client": "zerolabz-sentinel-py@1.1.0",
                "X-Sentinel-Policy": self.policy,
            },
        }

    def get_gemini_config(self) -> Dict[str, Any]:
        """
        Returns endpoint & header configuration for Google Gemini / Vertex AI REST callers:
        """
        root_url = self.base_url[:-3] if self.base_url.endswith("/v1") else self.base_url
        return {
            "endpoint": f"{root_url}/v1/chat/completions",
            "headers": {
                "Authorization": f"Bearer {self.api_key}",
                "X-Sentinel-Client": "zerolabz-sentinel-py@1.1.0",
                "X-Sentinel-Policy": self.policy,
            },
        }

    def health(self) -> Dict[str, Any]:
        root_url = self.base_url[:-3] if self.base_url.endswith("/v1") else self.base_url
        res = requests.get(f"{root_url}/v1/healthz", timeout=5.0)
        res.raise_for_status()
        return res.json()

    # --- Xero Runtime Recovery & SIEM APIs ---

    def get_mesh(self) -> Dict[str, Any]:
        root_url = self.base_url[:-3] if self.base_url.endswith("/v1") else self.base_url
        res = requests.get(f"{root_url}/api/mesh", timeout=5.0)
        res.raise_for_status()
        return res.json()

    def evaluate_telemetry(
        self,
        agent_id: str,
        drift_score: float,
        token_velocity: int = 35,
        cpu_usage: float = 25.0,
        memory_mb: int = 256,
        unauthorized_calls: int = 0,
    ) -> Dict[str, Any]:
        root_url = self.base_url[:-3] if self.base_url.endswith("/v1") else self.base_url
        payload = {
            "agent_id": agent_id,
            "drift_score": drift_score,
            "token_velocity": token_velocity,
            "cpu_usage": cpu_usage,
            "memory_mb": memory_mb,
            "unauthorized_calls": unauthorized_calls,
        }
        res = requests.post(f"{root_url}/api/telemetry/evaluate", json=payload, timeout=5.0)
        res.raise_for_status()
        return res.json()

    def trigger_recovery(self, agent_id: str) -> Dict[str, Any]:
        root_url = self.base_url[:-3] if self.base_url.endswith("/v1") else self.base_url
        res = requests.post(f"{root_url}/api/recovery/trigger", json={"agent_id": agent_id}, timeout=5.0)
        res.raise_for_status()
        return res.json()

    def get_siem_logs(self) -> Dict[str, Any]:
        root_url = self.base_url[:-3] if self.base_url.endswith("/v1") else self.base_url
        res = requests.get(f"{root_url}/api/siem/logs", timeout=5.0)
        res.raise_for_status()
        return res.json()
