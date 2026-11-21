#!/usr/bin/env python3
"""Unit tests for mosey-search-provider (pure stdlib, no live GNOME Shell)."""

from __future__ import annotations

import base64
import importlib.machinery
import importlib.util
from pathlib import Path
import unittest


def _load_provider():
    path = Path(__file__).resolve().parent / "mosey-search-provider"
    loader = importlib.machinery.SourceFileLoader("mosey_search_provider", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    # Register in sys.modules before exec_module so @dataclass works on Python 3.12+.
    import sys

    sys.modules[loader.name] = mod
    loader.exec_module(mod)
    return mod


provider = _load_provider()


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).rstrip(b"=").decode("ascii")


def _list_line(
    name: str,
    state: str,
    since: int = 1794651234,
    peer: str = "",
    fg: str = "",
    cwd: str = "",
    cmd: str = "",
) -> str:
    parts = ["MOSEY-LIST", "1"]
    if cmd:
        parts.append(f"cmd={_b64(cmd)}")
    if cwd:
        parts.append(f"cwd={_b64(cwd)}")
    if fg:
        parts.append(f"fg={_b64(fg)}")
    parts.append(f"name={name}")
    if peer:
        parts.append(f"peer={peer}")
    parts.append(f"since={since}")
    parts.append(f"state={state}")
    return " ".join(parts)


class SearchProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sample_output = "\n".join(
            [
                _list_line(
                    name="local-ipv4",
                    state="attached",
                    since=100,
                    peer="127.0.0.1:50000",
                    fg="claude",
                    cwd="~/Projects/local-v4",
                ),
                _list_line(
                    name="local-ipv6",
                    state="attached",
                    since=101,
                    peer="[::1]:50001",
                    fg="vim",
                    cwd="~/Projects/local-v6",
                ),
                _list_line(
                    name="pending-attach",
                    state="attached",
                    since=102,
                    peer="",
                    fg="bash",
                    cwd="~",
                ),
                _list_line(
                    name="starting-now",
                    state="new",
                    since=103,
                    fg="bash",
                    cwd="~",
                ),
                _list_line(
                    name="quiet-heron",
                    state="detached",
                    since=200,
                    peer="127.0.0.1:50002",
                    fg="claude",
                    cwd="~/Projects/foo",
                ),
                _list_line(
                    name="brave-otter",
                    state="attached",
                    since=300,
                    peer="100.64.1.2:41234",
                    fg="vim",
                    cwd="~/Projects/bar",
                ),
                _list_line(
                    name="remote-v6",
                    state="attached",
                    since=250,
                    peer="[2001:db8::7]:41234",
                    fg="claude",
                    cwd="~/Projects/ipv6",
                ),
            ]
        )
        self.sessions = provider.parse_list_output(self.sample_output)

    def test_locally_attached_sessions_are_never_returned(self) -> None:
        for query in (
            ["mosey"],
            ["local-ipv4"],
            ["local-ipv6"],
            ["pending-attach"],
            ["starting-now"],
            ["claude"],
            ["vim"],
            ["bash"],
        ):
            ids = [s.name for s in provider.match_sessions(self.sessions, query)]
            self.assertNotIn("local-ipv4", ids, f"query={query}")
            self.assertNotIn("local-ipv6", ids, f"query={query}")
            self.assertNotIn("pending-attach", ids, f"query={query}")
            self.assertNotIn("starting-now", ids, f"query={query}")

    def test_detached_session_is_returned_and_labelled_detached(self) -> None:
        matched = provider.match_sessions(self.sessions, ["quiet-heron"])
        self.assertEqual([s.name for s in matched], ["quiet-heron"])
        meta = provider.format_meta(matched[0])
        self.assertEqual(meta["id"], "quiet-heron")
        self.assertEqual(meta["name"], "claude \u00b7 ~/Projects/foo")
        self.assertEqual(meta["description"], "Detached \u00b7 quiet-heron")
        self.assertEqual(meta["gicon"], "mosey")

    def test_remotely_attached_session_is_returned_and_labelled_with_peer(self) -> None:
        matched = provider.match_sessions(self.sessions, ["brave-otter"])
        self.assertEqual([s.name for s in matched], ["brave-otter"])
        meta = provider.format_meta(matched[0])
        self.assertEqual(meta["id"], "brave-otter")
        self.assertEqual(meta["name"], "vim \u00b7 ~/Projects/bar")
        self.assertEqual(meta["description"], "Remote (100.64.1.2) \u00b7 brave-otter")
        self.assertEqual(meta["gicon"], "mosey")

        matched_v6 = provider.match_sessions(self.sessions, ["remote-v6"])
        self.assertEqual([s.name for s in matched_v6], ["remote-v6"])
        meta_v6 = provider.format_meta(matched_v6[0])
        self.assertEqual(meta_v6["description"], "Remote (2001:db8::7) \u00b7 remote-v6")

    def test_search_matches_mosey_name_fg_cwd_and_multiword_and(self) -> None:
        # "mosey" matches all eligible sessions, newest first.
        all_ids = [s.name for s in provider.match_sessions(self.sessions, ["MOSEY"])]
        self.assertEqual(all_ids, ["brave-otter", "remote-v6", "quiet-heron"])

        # Foreground program match (case-insensitive).
        claude_ids = [s.name for s in provider.match_sessions(self.sessions, ["CLAUDE"])]
        self.assertEqual(claude_ids, ["remote-v6", "quiet-heron"])

        # Directory match.
        foo_ids = [s.name for s in provider.match_sessions(self.sessions, ["Projects/FOO"])]
        self.assertEqual(foo_ids, ["quiet-heron"])

        # Multi-word AND across different fields.
        narrow = [s.name for s in provider.match_sessions(self.sessions, ["mosey", "claude", "foo"])]
        self.assertEqual(narrow, ["quiet-heron"])

        # Unmatched second term eliminates the candidate.
        none = provider.match_sessions(self.sessions, ["claude", "bar"])
        self.assertEqual(none, [])

        # Empty / whitespace terms match nothing.
        self.assertEqual(provider.match_sessions(self.sessions, []), [])
        self.assertEqual(provider.match_sessions(self.sessions, ["   "]), [])

    def test_format_meta_fallbacks_when_fg_or_cwd_missing(self) -> None:
        only_name = provider.Session(name="plain", state="detached")
        self.assertEqual(provider.format_meta(only_name)["name"], "plain")

        only_fg = provider.Session(name="plain", state="detached", fg="htop")
        self.assertEqual(provider.format_meta(only_fg)["name"], "htop")

        only_cwd = provider.Session(name="plain", state="detached", cwd="~/src")
        self.assertEqual(provider.format_meta(only_cwd)["name"], "plain \u00b7 ~/src")

    def test_activate_result_builds_expected_command(self) -> None:
        # Default kgx when present.
        cmd = provider.build_activate_command(
            "quiet-heron",
            env={},
            which=lambda name: "/usr/bin/kgx" if name == "kgx" else None,
        )
        self.assertEqual(cmd, ["kgx", "--", "mosey", "-s", "quiet-heron", "-close-if-idle"])

        # Fallback to gnome-terminal if kgx is absent.
        cmd = provider.build_activate_command(
            "quiet-heron",
            env={},
            which=lambda name: "/usr/bin/gnome-terminal" if name == "gnome-terminal" else None,
        )
        self.assertEqual(
            cmd,
            ["gnome-terminal", "--", "mosey", "-s", "quiet-heron", "-close-if-idle"],
        )

        # Fallback to ptyxis if kgx and gnome-terminal are absent.
        cmd = provider.build_activate_command(
            "quiet-heron",
            env={},
            which=lambda name: "/usr/bin/ptyxis" if name == "ptyxis" else None,
        )
        self.assertEqual(
            cmd,
            ["ptyxis", "--", "mosey", "-s", "quiet-heron", "-close-if-idle"],
        )

        # Explicit MOSEY_TERMINAL override.
        cmd = provider.build_activate_command(
            "quiet-heron",
            env={"MOSEY_TERMINAL": "ptyxis --new-window"},
            which=lambda _name: None,
        )
        self.assertEqual(
            cmd,
            ["ptyxis", "--new-window", "--", "mosey", "-s", "quiet-heron", "-close-if-idle"],
        )

        # LaunchSearch (no session name).
        cmd = provider.build_activate_command(
            None,
            env={},
            which=lambda name: "/usr/bin/kgx" if name == "kgx" else None,
        )
        self.assertEqual(cmd, ["kgx", "--", "mosey", "-close-if-idle"])

    def test_malformed_lines_are_ignored(self) -> None:
        noisy = "\n".join(
            [
                "not a mosey line",
                "MOSEY-LIST 2 name=future since=1 state=detached",
                "MOSEY-LIST 1 state=detached",
                "MOSEY-LIST 1 name=badstate since=1 state=gone",
                _list_line(name="good", state="detached"),
            ]
        )
        sessions = provider.parse_list_output(noisy)
        self.assertEqual([s.name for s in sessions], ["good"])


class DesktopEntryTests(unittest.TestCase):
    """The DesktopId named in the .ini must be one GNOME Shell will accept."""

    def _entry(self) -> dict[str, str]:
        path = Path(__file__).resolve().parent / "mosey.desktop"
        fields: dict[str, str] = {}
        for line in path.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                fields[key.strip()] = value.strip()
        return fields

    def test_desktop_entry_is_not_hidden_so_shell_loads_the_provider(self) -> None:
        # js/ui/remoteSearch.js drops a provider whose app fails should_show(),
        # silently; NoDisplay=true or Hidden=true makes it fail.
        entry = self._entry()
        self.assertNotEqual(entry.get("NoDisplay", "false").lower(), "true")
        self.assertNotEqual(entry.get("Hidden", "false").lower(), "true")

    def test_launching_the_app_opens_a_new_session(self) -> None:
        self.assertEqual(self._entry()["Exec"], "kgx -- mosey -new -close-if-idle")


if __name__ == "__main__":
    unittest.main()
