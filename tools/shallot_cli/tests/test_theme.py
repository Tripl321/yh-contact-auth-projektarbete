"""Tester för färgtemat (shallot_cli.theme) och NO_COLOR/FORCE_COLOR."""

from shallot_cli import theme, tui


def test_fg_default_emits_ansi(monkeypatch):
    monkeypatch.setattr(theme, "USE_COLOR", True)
    assert theme.fg("hej", theme.ORANGE) == "\x1b[38;2;255;140;0mhej\x1b[0m"


def test_fg_when_no_color_is_plain(monkeypatch):
    monkeypatch.setattr(theme, "USE_COLOR", False)
    assert theme.fg("hej", theme.ORANGE) == "hej"
    assert theme.accent("x") == "x"
    assert theme.dim("x") == "x"


def test_paint_preserves_lines(monkeypatch):
    monkeypatch.setattr(theme, "USE_COLOR", True)
    painted = theme.paint("a\nb", theme.ORANGE)
    assert painted.splitlines()[0].startswith("\x1b[")
    assert painted.endswith("b\x1b[0m")


def test_no_color_env_disables(monkeypatch):
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    assert theme._enabled() is False


def test_force_color_enables_without_no_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert theme._enabled() is True


def test_no_color_wins_over_force(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert theme._enabled() is False


def test_menu_text_colored_when_enabled(monkeypatch):
    monkeypatch.setattr(theme, "USE_COLOR", True)
    assert "\x1b[" in tui._menu_text()


def test_menu_text_plain_when_no_color(monkeypatch):
    monkeypatch.setattr(theme, "USE_COLOR", False)
    assert "\x1b[" not in tui._menu_text()


def test_demo_header_respects_no_color(monkeypatch):
    from shallot_cli import demo
    monkeypatch.setattr(theme, "USE_COLOR", True)
    colored = demo.render_header()
    monkeypatch.setattr(theme, "USE_COLOR", False)
    plain = demo.render_header()
    assert "\x1b[" in colored
    assert "\x1b[" not in plain
    assert colored.replace("\x1b[38;2;255;140;0m", "").replace("\x1b[0m", "") \
        == plain