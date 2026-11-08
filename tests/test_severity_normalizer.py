from core.severity_normalizer import SeverityNormalizer


normalizer = SeverityNormalizer()


def test_critical():
    assert normalizer.normalize("critical") == "Critical"


def test_high():
    assert normalizer.normalize("high") == "High"


def test_medium():
    assert normalizer.normalize("medium") == "Medium"


def test_low():
    assert normalizer.normalize("low") == "Low"


def test_info():
    assert normalizer.normalize("info") == "Info"


def test_unknown_defaults_to_info():
    assert normalizer.normalize("something-weird") == "Info"