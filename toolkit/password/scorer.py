"""Scoring engine — converts analysis into a 0-100 score with explanations."""

from dataclasses import dataclass, field
from .analyzer import AnalysisResult
from .patterns import PatternMatch
from .breach_checker import BreachResult

STRENGTH_LABELS = [(0, 20, "Very Weak", "red"), (20, 40, "Weak", "yellow"),
                   (40, 60, "Fair", "bright_yellow"), (60, 80, "Strong", "green"),
                   (80, 101, "Very Strong", "bright_green")]


@dataclass
class ScoreResult:
    score: int = 0
    label: str = "Very Weak"
    color: str = "red"
    breakdown: list[dict] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


class PasswordScorer:
    def score(self, analysis: AnalysisResult, patterns: list[PatternMatch], breach: BreachResult) -> ScoreResult:
        r = ScoreResult()
        total = 0

        # Length (0-25)
        ls = min(25, analysis.length * 2)
        total += ls
        r.breakdown.append({"factor": "Length", "points": ls, "max": 25,
                            "detail": f"{analysis.length} chars"})
        if analysis.length < 8:
            r.suggestions.append("Use at least 12 characters — length is the biggest factor")
        elif analysis.length < 12:
            r.suggestions.append("Extend to 14+ characters for better security")

        # Entropy (0-25)
        es = min(25, int(analysis.entropy / 3))
        total += es
        r.breakdown.append({"factor": "Entropy", "points": es, "max": 25,
                            "detail": f"{analysis.entropy:.1f} bits"})

        # Char variety (0-20)
        vs = analysis.char_class_count * 5
        total += vs
        missing = []
        if not analysis.has_uppercase: missing.append("uppercase")
        if not analysis.has_lowercase: missing.append("lowercase")
        if not analysis.has_digits: missing.append("numbers")
        if not analysis.has_special: missing.append("special chars (!@#$)")
        if missing:
            r.suggestions.append(f"Add {', '.join(missing)}")
        r.breakdown.append({"factor": "Char variety", "points": vs, "max": 20,
                            "detail": f"{analysis.char_class_count}/4 classes"})

        # Uniqueness (0-10)
        us = min(10, int(analysis.unique_ratio * 10))
        total += us
        if analysis.unique_ratio < 0.6:
            r.suggestions.append("Use more distinct characters")
        r.breakdown.append({"factor": "Uniqueness", "points": us, "max": 10,
                            "detail": f"{analysis.unique_ratio:.0%} unique"})

        # Pattern penalties
        penalty = 0
        seen = set()
        weights = {"high": 10, "medium": 5, "low": 2}
        for p in patterns:
            if p.pattern_type not in seen:
                penalty += weights.get(p.severity, 3)
                seen.add(p.pattern_type)
        penalty = min(30, penalty)
        if penalty:
            total -= penalty
            r.breakdown.append({"factor": "Pattern penalties", "points": -penalty, "max": 0,
                                "detail": f"{len(patterns)} weak pattern(s)"})

        # Breach penalty
        if breach.is_breached:
            total -= 30
            r.suggestions.insert(0, "BREACHED — do NOT use this password")
            r.breakdown.append({"factor": "Breach detected", "points": -30, "max": 0,
                                "detail": "Found in compromised database"})

        r.score = max(0, min(100, total))
        for lo, hi, label, color in STRENGTH_LABELS:
            if lo <= r.score < hi:
                r.label, r.color = label, color
                break
        if not r.suggestions:
            r.suggestions.append("Solid password — consider a passphrase for even more security")
        return r
