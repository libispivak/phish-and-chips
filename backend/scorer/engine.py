"""Combines signals into a score (0-100), a verdict and the reasons."""

from dataclasses import asdict

from .parser import ParsedEmail, parse_email
from .signals import ALL_CHECKS, STRONG, WEAK

WEAK_SIGNALS_CAP = 30        # many small oddities alone can't make an email "malicious"
DECEPTION_FLOOR = 70         # deception + harmful call to action => malicious
SUSPICIOUS_FROM = 25
MALICIOUS_FROM = 60


def verdict_for(score: int) -> str:
    if score >= MALICIOUS_FROM:
        return "malicious"
    if score >= SUSPICIOUS_FROM:
        return "suspicious"
    return "safe"


def score_parsed(email: ParsedEmail) -> dict:
    signals = [s for s in (check(email) for check in ALL_CHECKS) if s is not None]

    strong_points = sum(s.points for s in signals if s.strength == STRONG)
    weak_points = min(WEAK_SIGNALS_CAP, sum(s.points for s in signals if s.strength == WEAK))
    score = min(100, strong_points + weak_points)

    deceptive = any(s.deceptive for s in signals)
    asks_to_act = any(s.call_to_action for s in signals)
    if deceptive and asks_to_act:
        score = max(score, DECEPTION_FLOOR)

    signals.sort(key=lambda s: (s.strength != STRONG, -s.points))
    return {
        "score": score,
        "verdict": verdict_for(score),
        "deception_and_action": deceptive and asks_to_act,
        "signals": [asdict(s) for s in signals],
    }


def score_email(raw: bytes) -> dict:
    return score_parsed(parse_email(raw))
