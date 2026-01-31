import ipaddress
import re
from urllib.parse import urlparse

def detect_ioc_type(ioc: str) -> str:
    ioc = ioc.strip()

    # IP
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass

    # URL
    p = urlparse(ioc)
    if p.scheme in ("http", "https") and p.netloc:
        return "url"

    # Hashes
    if re.fullmatch(r"[a-fA-F0-9]{32}", ioc):
        return "md5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", ioc):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", ioc):
        return "sha256"

    # Domain (simple validation)
    if re.fullmatch(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", ioc):
        return "domain"

    return "unknown"
