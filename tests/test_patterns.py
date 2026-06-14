from toolkit.password.patterns import PatternDetector


detector = PatternDetector(common_words=["password", "dragon", "monkey", "shadow"])


def test_keyboard_walk():
    matches = detector.detect_all("myqwerty123")
    types = [m.pattern_type for m in matches]
    assert "keyboard_walk" in types


def test_dictionary_word():
    matches = detector.detect_all("dragon99")
    types = [m.pattern_type for m in matches]
    assert "dictionary_word" in types


def test_repeated_chars():
    matches = detector.detect_all("aaa111bbb")
    types = [m.pattern_type for m in matches]
    assert "repeated_chars" in types


def test_date_pattern():
    matches = detector.detect_all("born2005yeah")
    types = [m.pattern_type for m in matches]
    assert "date_pattern" in types


def test_leet_speak():
    matches = detector.detect_all("p@$$w0rd")
    types = [m.pattern_type for m in matches]
    assert "leet_speak" in types


def test_common_suffix():
    matches = detector.detect_all("hello123")
    types = [m.pattern_type for m in matches]
    assert "common_suffix" in types


def test_strong_password_no_patterns():
    matches = detector.detect_all("Xk9#mP2$vL7!")
    assert len(matches) == 0
