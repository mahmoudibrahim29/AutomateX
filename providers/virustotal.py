from utils.http import safe_get

VT_BASE = "https://www.virustotal.com/api/v3"

class VirusTotalClient:
    def __init__(self, api_key: str, timeout: int = 20):
        self.api_key = api_key
        self.timeout = timeout

    def _get(self, path: str) -> dict:
        url = f"{VT_BASE}{path}"
        headers = {"x-apikey": self.api_key}
        r = safe_get(url, headers=headers, timeout=self.timeout)
        return r.json()

    def lookup_ip(self, ip: str) -> dict:
        return self._get(f"/ip_addresses/{ip}")

    def lookup_domain(self, domain: str) -> dict:
        return self._get(f"/domains/{domain}")

    def lookup_hash(self, file_hash: str) -> dict:
        return self._get(f"/files/{file_hash}")

    def lookup_url(self, url_id: str) -> dict:
        return self._get(f"/urls/{url_id}")
