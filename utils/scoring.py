def score_from_vt(vt_stats: dict | None) -> dict:
    """
    VT stats example:
      {"harmless": 80, "malicious": 2, "suspicious": 1, "undetected": 10, ...}
    Returns a score 0..100 and verdict.
    """
    if not vt_stats:
        return {"score": 0, "verdict": "unknown"}

    malicious = int(vt_stats.get("malicious", 0))
    suspicious = int(vt_stats.get("suspicious", 0))

    # Simple heuristic
    score = (malicious * 20) + (suspicious * 10)
    score = max(0, min(100, score))

    if score >= 70:
        verdict = "malicious"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {"score": score, "verdict": verdict}
