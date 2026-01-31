import time
import random
import requests

def safe_get(url: str, *, headers=None, params=None, timeout=20, max_retries=5):
    for attempt in range(max_retries):
        r = requests.get(url, headers=headers, params=params, timeout=timeout)

        # Rate limit or transient server errors
        if r.status_code == 429 or (500 <= r.status_code < 600):
            sleep_s = min(2 ** attempt, 30) + random.uniform(0, 1)
            time.sleep(sleep_s)
            continue

        r.raise_for_status()
        return r

    r.raise_for_status()
    return r
