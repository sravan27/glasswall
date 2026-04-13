from glasswall.registry import choose_group_target_version, choose_target_version


def test_choose_target_version_prefers_minimum_python_fix() -> None:
    assert choose_target_version("PyPI", "2.19.0", ("2.33.0", "2.31.0", "2.20.0")) == "2.20.0"


def test_choose_target_version_prefers_minimum_npm_fix() -> None:
    assert choose_target_version("npm", "4.17.20", ("4.17.21", "5.0.0")) == "4.17.21"


def test_choose_group_target_version_clears_all_visible_python_advisories() -> None:
    assert (
        choose_group_target_version("PyPI", "2.19.0", (("2.20.0",), ("2.31.0",), ("2.33.0",)))
        == "2.33.0"
    )
