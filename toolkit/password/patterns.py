"""Pattern detection — keyboard walks, dictionary words, leet speak, dates."""

import re
from dataclasses import dataclass


@dataclass
class PatternMatch:
    pattern_type: str
    matched: str
    severity: str  # low, medium, high
    description: str


class PatternDetector:
    KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
    LEET_MAP = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"}
    DATE_PATTERNS = [r"\b(19|20)\d{2}\b", r"\b\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}\b"]

    def __init__(self, common_words: list[str] | None = None):
        self.common_words = set(w.lower() for w in (common_words or []))
        self.keyboard_seqs = self._build_keyboard_seqs()

    def _build_keyboard_seqs(self) -> list[str]:
        seqs = []
        for row in self.KEYBOARD_ROWS:
            for ln in range(3, min(6, len(row)) + 1):
                for i in range(len(row) - ln + 1):
                    s = row[i:i + ln]
                    seqs.extend([s, s[::-1]])
        return seqs

    def detect_all(self, password: str) -> list[PatternMatch]:
        out: list[PatternMatch] = []
        lower = password.lower()
        for seq in self.keyboard_seqs:
            if seq in lower:
                out.append(PatternMatch("keyboard_walk", seq,
                    "high" if len(seq) >= 4 else "medium",
                    f"Keyboard walk '{seq}' — attackers try these first"))
        for m in re.finditer(r"(.)\1{2,}", password):
            out.append(PatternMatch("repeated_chars", m.group(), "medium",
                f"Repeated '{m.group(1)}' ×{len(m.group())} adds no entropy"))
        for word in self.common_words:
            if len(word) >= 3 and word in lower:
                out.append(PatternMatch("dictionary_word", word,
                    "high" if len(word) >= 5 else "medium",
                    f"Contains '{word}' — vulnerable to dictionary attacks"))
        for pat in self.DATE_PATTERNS:
            for m in re.finditer(pat, password):
                out.append(PatternMatch("date_pattern", m.group(), "medium",
                    f"Date-like '{m.group()}' — easily guessed"))
        decoded = "".join(self.LEET_MAP.get(c, c) for c in lower)
        for word in self.common_words:
            if len(word) >= 4 and word in decoded and word not in lower:
                out.append(PatternMatch("leet_speak", word, "medium",
                    f"Leet-speak of '{word}' — cracking tools decode these"))
                break
        suffix = re.search(r"[a-zA-Z]([!@#$%^&*\d]{1,4})$", password)
        if suffix and suffix.group(1) in {"1", "12", "123", "!", "1!", "69", "99"}:
            out.append(PatternMatch("common_suffix", suffix.group(1), "medium",
                f"Common suffix '{suffix.group(1)}' — appended to every dictionary word by crackers"))
        return out
