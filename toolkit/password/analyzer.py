"""Core password analysis — entropy, character classes, structural metrics."""

import math
import re
import string
from dataclasses import dataclass, field


@dataclass
class AnalysisResult:
    length: int = 0
    entropy: float = 0.0
    char_classes: dict = field(default_factory=dict)
    char_class_count: int = 0
    has_uppercase: bool = False
    has_lowercase: bool = False
    has_digits: bool = False
    has_special: bool = False
    unique_chars: int = 0
    unique_ratio: float = 0.0
    consecutive_repeats: int = 0
    sequential_chars: int = 0


class PasswordAnalyzer:
    """Structural and statistical analysis of a password."""

    CHAR_POOLS = {
        "lowercase": (r"[a-z]", 26),
        "uppercase": (r"[A-Z]", 26),
        "digits": (r"\d", 10),
        "special": (r"[^\w\s]", 32),
    }

    def analyze(self, password: str) -> AnalysisResult:
        if not password:
            return AnalysisResult()

        result = AnalysisResult(length=len(password))
        result.char_classes = {k: bool(re.search(p, password)) for k, (p, _) in self.CHAR_POOLS.items()}
        result.char_class_count = sum(result.char_classes.values())
        result.has_uppercase = result.char_classes["uppercase"]
        result.has_lowercase = result.char_classes["lowercase"]
        result.has_digits = result.char_classes["digits"]
        result.has_special = result.char_classes["special"]
        result.unique_chars = len(set(password))
        result.unique_ratio = result.unique_chars / len(password)
        result.entropy = self._entropy(password)
        result.consecutive_repeats = len(re.findall(r"(.)\1{2,}", password))
        result.sequential_chars = self._count_sequential(password)
        return result

    def _entropy(self, password: str) -> float:
        pool = sum(size for (pat, size) in self.CHAR_POOLS.values() if re.search(pat, password))
        pool = pool or 128
        return round(len(password) * math.log2(pool), 2)

    def _count_sequential(self, password: str) -> int:
        count = 0
        for i in range(len(password) - 2):
            a, b, c = ord(password[i]), ord(password[i + 1]), ord(password[i + 2])
            if (b - a == 1 and c - b == 1) or (a - b == 1 and b - c == 1):
                count += 1
        return count
