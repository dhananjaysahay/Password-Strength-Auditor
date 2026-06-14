from toolkit.password.analyzer import PasswordAnalyzer, AnalysisResult
from toolkit.password.patterns import PatternDetector
from toolkit.password.breach_checker import BreachResult
from toolkit.password.scorer import PasswordScorer


analyzer = PasswordAnalyzer()
detector = PatternDetector(common_words=["password", "admin"])
scorer = PasswordScorer()


def test_weak_password_scores_low():
    a = analyzer.analyze("123456")
    p = detector.detect_all("123456")
    b = BreachResult(is_breached=True)
    s = scorer.score(a, p, b)
    assert s.score < 20
    assert s.label in ("Very Weak", "Weak")


def test_strong_password_scores_high():
    a = analyzer.analyze("Xk9#mP2$vL7!qR4@")
    p = detector.detect_all("Xk9#mP2$vL7!qR4@")
    b = BreachResult(is_breached=False)
    s = scorer.score(a, p, b)
    assert s.score >= 70
    assert s.label in ("Strong", "Very Strong")


def test_breach_penalty():
    a = analyzer.analyze("GoodPass99!")
    p = detector.detect_all("GoodPass99!")
    clean = scorer.score(a, p, BreachResult(is_breached=False))
    breached = scorer.score(a, p, BreachResult(is_breached=True))
    assert breached.score < clean.score


def test_suggestions_present():
    a = analyzer.analyze("abc")
    p = detector.detect_all("abc")
    b = BreachResult(is_breached=False)
    s = scorer.score(a, p, b)
    assert len(s.suggestions) > 0


def test_score_in_range():
    for pw in ["", "a", "abc123", "Str0ng!Pass#2024", "aaaaaa"]:
        a = analyzer.analyze(pw) if pw else AnalysisResult()
        p = detector.detect_all(pw)
        b = BreachResult(is_breached=False)
        s = scorer.score(a, p, b)
        assert 0 <= s.score <= 100
