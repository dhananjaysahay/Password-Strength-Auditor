from toolkit.password.analyzer import PasswordAnalyzer


analyzer = PasswordAnalyzer()


def test_empty_password():
    r = analyzer.analyze("")
    assert r.length == 0
    assert r.entropy == 0.0


def test_short_password():
    r = analyzer.analyze("abc")
    assert r.length == 3
    assert r.has_lowercase
    assert not r.has_uppercase
    assert r.char_class_count == 1


def test_mixed_password():
    r = analyzer.analyze("Test1234!")
    assert r.has_uppercase
    assert r.has_lowercase
    assert r.has_digits
    assert r.has_special
    assert r.char_class_count == 4


def test_entropy_increases_with_pool():
    r1 = analyzer.analyze("aaaa")      # 1 class
    r2 = analyzer.analyze("aA1!")      # 4 classes, same length
    assert r2.entropy > r1.entropy


def test_consecutive_repeats():
    r = analyzer.analyze("aaabbb")
    assert r.consecutive_repeats == 2


def test_sequential_chars():
    r = analyzer.analyze("abcdef")
    assert r.sequential_chars > 0


def test_unique_ratio():
    r = analyzer.analyze("aaaaaa")
    assert r.unique_ratio < 0.2
    r2 = analyzer.analyze("abcdef")
    assert r2.unique_ratio == 1.0
