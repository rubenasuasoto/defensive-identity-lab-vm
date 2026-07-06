from identitylab.verify import UrlCheck, checks_passed


def test_checks_passed_requires_all_checks_ok() -> None:
    assert checks_passed([UrlCheck("demo", "https://example.test", 200, True)])
    assert not checks_passed(
        [
            UrlCheck("demo", "https://example.test", 200, True),
            UrlCheck("docs", "https://example.test/docs", 404, False),
        ]
    )
