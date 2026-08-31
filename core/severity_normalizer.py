class SeverityNormalizer:

    SEVERITIES=["Critical","High","Medium","Low","Info"]
    SEVERIY_MAP={
        "critical":"Critical",
        "crit":"Critical",
        "high":"High",
        "medium":"Medium",
        "med":"Medium",
        "low":"Low",
        "info":"Info",
        "informational":"Info",
        "information":"Info",
        "information":"Info",
        "unknown":"Info",
        "none":"Info",
        "":"Info",
    }
    def normalize(self,severity):
        if severity is None:
            return "Info"
        severity=str(severity).strip().lower()
        return self.SEVERIY_MAP.get(severity,"Info")

if __name__ == "__main__":

    normalizer = SeverityNormalizer()

    test_values = [
        "CRITICAL",
        "High",
        "MEDIUM",
        "low",
        "informational",
        "unknown",
        None,
        "something"
    ]

    for value in test_values:
        print(f"{value!r} -> {normalizer.normalize(value)}")