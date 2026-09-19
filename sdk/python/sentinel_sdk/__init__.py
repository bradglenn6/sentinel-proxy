import os
import requests
from typing import Optional, Dict, Any

class SentinelClient:
    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.base_url = (base_url or os.getenv("SENTINEL_BASE_URL", "https://sentinel.zrolabz.com/v1")).rstrip("/")
        self.api_key = api_key or os.getenv("SENTINEL_API_KEY", "sentinel-stateless")

    def get_openai_config(self) -> Dict[str, Any]:
        """
        Returns configuration compatible with OpenAI Python SDK v1.0+:
        client = OpenAI(**sentinel.get_openai_config())
        """
        return {
            "base_url": self.base_url,
            "api_key": self.api_key,
            "default_headers": {
                "X-Sentinel-Client": "zerolabz-sentinel-py@1.0.0"
            }
        }

    def health(self) -> Dict[str, Any]:
        res = requests.get(f"{self.base_url}/healthz", timeout=5.0)
        res.raise_for_status()
        return res.json()
