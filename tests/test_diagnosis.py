"""The local diagnosis file.

Three things are pinned here, each with a fabricated failure:

1. A crashed reader is a defect of the tool: the run continues with the other
   readers, says so in red, writes ``jochwacht-sbom-diagnosis.json`` next to
   the SBOM and ends with exit 1. A crash outside a reader does the same.
2. The boundary — the file contains nothing the customer would not show a
   stranger: no package names, versions, paths, file contents, environment
   variables, host names, and never the exception message.
3. "Werkzeug kaputt" and "Bausystem nicht unterstützt" are told apart: an
   unread build system is a ``kind: unsupported_build`` file listing only
   OUR marker labels with counts, exit code 2 as before; a clean run writes
   no file at all.
"""

from __future__ import annotations

import json
import os
import platform
from pathlib import Path

import pytest
from click.testing import CliRunner

from jochwacht_sbom import cli as check_cli
from jochwacht_sbom import diagnosis
from jochwacht_sbom.analyzer.pipeline import run_pipeline, tier2_structured
from jochwacht_sbom.analyzer.scanner import collect_build_files
from jochwacht_sbom.sbom import scanner as sbom_scanner

# Fabricated customer data: none of these strings may ever reach the file.
_SECRET_DIR = "acme-secret-project-x9"
_SECRET_PKG = "top-secret-pkg"
_SECRET_VERSION = "1.2.3"
_SECRET_KEY = "org.acme:internal-crypto-lib"
_SECRET_ENV = "hunter2-fabricated-token"
_SECRET_FILE_CONTENT = "<!-- customer comment: project falcon -->"


def _secret_project(tmp_path: Path) -> Path:
    """A project whose every identifier is a canary."""
    proj = tmp_path / _SECRET_DIR
    proj.mkdir()
    (proj / "requirements.txt").write_text(
        f"{_SECRET_PKG}=={_SECRET_VERSION}\n", encoding="utf-8",
    )
    (proj / "pom.xml").write_text(
        f'<?xml version="1.0"?>\n{_SECRET_FILE_CONTENT}\n'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<modelVersion>4.0.0</modelVersion><groupId>acme</groupId>"
        "<artifactId>falcon</artifactId><version>1</version></project>\n",
        encoding="utf-8",
    )
    return proj


def _crashing_reader(path: Path) -> list[sbom_scanner.Dependency]:
    # The message carries a customer identifier on purpose — it must not
    # reach the file (a KeyError's message is the key).
    raise KeyError(_SECRET_KEY)


@pytest.fixture
def broken_pom_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sbom_scanner._SCANNER_FUNCS, "pom_xml", _crashing_reader)


def _canaries(proj: Path) -> list[str]:
    return [
        _SECRET_DIR, _SECRET_PKG, _SECRET_VERSION, _SECRET_KEY, _SECRET_ENV,
        "project falcon", str(proj), str(proj.parent),
    ]


class TestReaderCrash:
    """1. A crashed reader: run continues, red line, file, exit 1."""

    def test_run_continues_writes_file_and_exits_one(
        self, tmp_path: Path, broken_pom_reader: None,
    ) -> None:
        proj = _secret_project(tmp_path)
        res = CliRunner().invoke(check_cli.main, [str(proj)])
        assert res.exit_code == 1, res.output
        # The other reader's result is still delivered …
        sbom = json.loads((proj / "sbom.cdx.json").read_text(encoding="utf-8"))
        assert any(c["name"] == _SECRET_PKG for c in sbom["components"])
        # … the customer is told which reader, what type, whose fault …
        assert "1 reader failed" in res.output
        assert "pom.xml (KeyError)" in res.output
        assert "INCOMPLETE" in res.output
        assert "not in your project" in res.output
        assert diagnosis.SUPPORT_ADDRESS in res.output
        assert "Nothing is sent automatically" in res.output
        # … and the file lies next to the SBOM.
        diag = proj / diagnosis.DIAGNOSIS_FILENAME
        assert diag.is_file()
        assert str(diag) in res.output
        report = json.loads(diag.read_text(encoding="utf-8"))
        assert report["kind"] == "tool_error"
        assert report["tool_version"]
        assert report["python"] == platform.python_version()
        [failure] = report["failures"]
        assert failure["reader"] == "pom_xml"
        assert failure["pattern"] == "pom.xml"
        assert failure["exc_type"] == "KeyError"
        # Frames are package-relative and end in the reader itself.
        assert failure["frames"], failure
        assert all(not f.startswith("/") and ":\\" not in f for f in failure["frames"])
        assert any(f.startswith("sbom/scanner.py:_read_with:") for f in failure["frames"])

    def test_file_lands_next_to_an_explicit_sbom_path(
        self, tmp_path: Path, broken_pom_reader: None,
    ) -> None:
        proj = _secret_project(tmp_path)
        elsewhere = tmp_path / "out"
        elsewhere.mkdir()
        res = CliRunner().invoke(
            check_cli.main, [str(proj), "--sbom", str(elsewhere / "bill.json")],
        )
        assert res.exit_code == 1, res.output
        assert (elsewhere / diagnosis.DIAGNOSIS_FILENAME).is_file()
        assert not (proj / diagnosis.DIAGNOSIS_FILENAME).exists()

    def test_dry_run_and_output_also_exit_one(
        self, tmp_path: Path, broken_pom_reader: None,
    ) -> None:
        proj = _secret_project(tmp_path)
        res = CliRunner().invoke(check_cli.main, [str(proj), "--dry-run"])
        assert res.exit_code == 1, res.output
        assert "1 reader failed" in res.output
        out = tmp_path / "payload.json"
        res = CliRunner().invoke(check_cli.main, [str(proj), "--output", str(out)])
        assert res.exit_code == 1, res.output
        assert out.is_file()  # the customer's explicit hand-off still happens

    def test_pipeline_scanner_crash_is_recorded_by_tier_and_type(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        proj = _secret_project(tmp_path)

        def _boom(self: object, file_type: str, file_path: Path, project_path: Path) -> None:
            raise IndexError(_SECRET_KEY)

        monkeypatch.setattr(tier2_structured.PomXmlParser, "scan", _boom)
        build_files = collect_build_files(proj)
        run_pipeline(proj, build_files, enabled_tiers={2})
        [failure] = diagnosis.failures()
        assert failure.reader == "tier2:structured-pom-xml"
        assert failure.pattern == "maven"       # the file TYPE from our table
        assert failure.exc_type == "IndexError"
        assert _SECRET_KEY not in json.dumps(diagnosis.tool_error_report(
            [failure], build_files_scanned=len(build_files),
        ))

    def test_crash_outside_a_reader_writes_file_and_hides_traceback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        proj = _secret_project(tmp_path)

        def _boom(**kwargs: object) -> None:
            raise RuntimeError(_SECRET_KEY)

        monkeypatch.setattr(check_cli, "build_payload", _boom)
        monkeypatch.delenv(diagnosis.TRACEBACK_ENV, raising=False)
        res = CliRunner().invoke(check_cli.main, [str(proj)])
        assert res.exit_code == 1, res.output
        assert "internal error (RuntimeError)" in res.output
        assert "Traceback" not in res.output
        assert _SECRET_KEY not in res.output
        report = json.loads(
            (proj / diagnosis.DIAGNOSIS_FILENAME).read_text(encoding="utf-8"),
        )
        assert report["kind"] == "tool_error"
        [failure] = report["failures"]
        assert failure["reader"] == ""
        assert failure["exc_type"] == "RuntimeError"
        assert any(f.startswith("cli.py:_run:") for f in failure["frames"])

    def test_traceback_env_reraises_for_developers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        proj = _secret_project(tmp_path)

        def _boom(**kwargs: object) -> None:
            raise RuntimeError("dev wants the trace")

        monkeypatch.setattr(check_cli, "build_payload", _boom)
        monkeypatch.setenv(diagnosis.TRACEBACK_ENV, "1")
        res = CliRunner().invoke(check_cli.main, [str(proj)])
        assert isinstance(res.exception, RuntimeError)
        assert not (proj / diagnosis.DIAGNOSIS_FILENAME).exists()

    def test_ctrl_c_in_the_confirmation_is_not_a_tool_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        proj = _secret_project(tmp_path)
        monkeypatch.setattr(check_cli, "_stdin_is_terminal", lambda: True)
        monkeypatch.setattr(check_cli.click, "confirm", lambda *a, **k: (_ for _ in ()).throw(
            check_cli.click.Abort(),
        ))
        res = CliRunner().invoke(
            check_cli.main, [str(proj), "--send"],
            env={"JOCHWACHT_API_KEY": "jw_test_" + "k" * 24},
        )
        assert res.exit_code == 1
        assert "Aborted" in res.output
        assert not (proj / diagnosis.DIAGNOSIS_FILENAME).exists()


class TestBoundary:
    """2. Nothing the customer would not show a stranger."""

    def test_file_contains_none_of_the_canaries(
        self, tmp_path: Path, broken_pom_reader: None, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("ACME_TOKEN", _SECRET_ENV)
        proj = _secret_project(tmp_path)
        res = CliRunner().invoke(check_cli.main, [str(proj)])
        assert res.exit_code == 1, res.output
        text = (proj / diagnosis.DIAGNOSIS_FILENAME).read_text(encoding="utf-8")
        for canary in _canaries(proj):
            assert canary not in text, canary
        # No environment variable value at all.
        for value in os.environ.values():
            if len(value) >= 8:
                assert value not in text, "environment value leaked"
        # No host name.
        node = platform.node()
        if len(node) >= 3:
            assert node not in text
        # And the file says what it is, in the first key.
        report = json.loads(text)
        assert next(iter(report)) == "_about"
        assert diagnosis.SUPPORT_ADDRESS in report["_about"]
        assert "leaves your machine only if you send it" in report["_about"]

    def test_frames_are_package_relative_and_stop_at_the_package(self) -> None:
        def _outer() -> None:
            _inner()

        def _inner() -> None:
            raise ValueError(_SECRET_KEY)

        try:
            _outer()
        except ValueError as exc:
            frames = diagnosis.own_frames(exc)
        # This test file is not inside the package: nothing is kept.
        assert frames == []

    def test_reader_frames_carry_no_absolute_path(self, tmp_path: Path) -> None:
        pom = tmp_path / "pom.xml"
        pom.write_text("not xml at all <<<", encoding="utf-8")

        def _crash(path: Path) -> list[sbom_scanner.Dependency]:
            raise KeyError(str(path))

        frames = sbom_scanner._read_with("pom_xml", "pom.xml", _crash, pom)
        assert frames == []
        [failure] = diagnosis.failures()
        assert failure.frames == [
            f for f in failure.frames if f.startswith("sbom/scanner.py:_read_with:")
        ]
        assert str(tmp_path) not in json.dumps(diagnosis.tool_error_report(
            [failure], build_files_scanned=0,
        ))

    def test_platform_line_has_no_host_name(self) -> None:
        report = diagnosis.tool_error_report([], build_files_scanned=0)
        node = platform.node()
        if len(node) >= 3:
            assert node not in str(report["platform"])
        assert report["platform"]

    def test_stats_in_the_payload_carry_no_diagnosis(
        self, tmp_path: Path, broken_pom_reader: None,
    ) -> None:
        # The payload is what --send transmits: the diagnosis must not ride
        # along in it (no silent sending, even of sanitised data).
        proj = _secret_project(tmp_path)
        res = CliRunner().invoke(check_cli.main, [str(proj), "--dry-run"])
        payload = json.loads(res.stdout)
        assert "failures" not in json.dumps(payload)
        assert "KeyError" not in json.dumps(payload)


class TestUnsupportedBuild:
    """3. "Bausystem nicht unterstützt" is a roadmap line, not a defect."""

    def test_unread_build_system_writes_marker_file_and_keeps_exit_two(
        self, tmp_path: Path,
    ) -> None:
        proj = tmp_path / _SECRET_DIR
        proj.mkdir()
        (proj / "BUILD.bazel").write_text("cc_library(name = 'falcon')\n", encoding="utf-8")
        (proj / "WORKSPACE").write_text("", encoding="utf-8")
        (proj / "fw").mkdir()
        (proj / "fw" / "falcon-secret.uvprojx").write_text("<Project/>", encoding="utf-8")
        res = CliRunner().invoke(check_cli.main, [str(proj)])
        assert res.exit_code == 2, res.output
        assert "No supported build system found" in res.output
        assert "does not read yet: bazel (2), keil (1)" in res.output
        assert diagnosis.SUPPORT_ADDRESS in res.output
        text = (proj / diagnosis.DIAGNOSIS_FILENAME).read_text(encoding="utf-8")
        report = json.loads(text)
        assert report["kind"] == "unsupported_build"
        assert report["unsupported_markers"] == {"bazel": 2, "keil": 1}
        assert "failures" not in report
        for canary in ("falcon", _SECRET_DIR, str(proj)):
            assert canary not in text, canary

    def test_empty_directory_writes_no_file(self, tmp_path: Path) -> None:
        proj = tmp_path / "nothing"
        proj.mkdir()
        (proj / "README.md").write_text("hi\n", encoding="utf-8")
        res = CliRunner().invoke(check_cli.main, [str(proj)])
        assert res.exit_code == 2, res.output
        assert not (proj / diagnosis.DIAGNOSIS_FILENAME).exists()
        assert "does not read yet" not in res.output

    def test_read_beside_unread_is_named_but_no_file(self, tmp_path: Path) -> None:
        proj = tmp_path / "mixed"
        proj.mkdir()
        (proj / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
        (proj / "BUILD.bazel").write_text("", encoding="utf-8")
        res = CliRunner().invoke(check_cli.main, [str(proj)])
        assert res.exit_code == 0, res.output
        assert "Not read (no reader yet): bazel (1)" in res.output
        assert not (proj / diagnosis.DIAGNOSIS_FILENAME).exists()

    def test_markers_respect_exclusions_and_ignore_file(self, tmp_path: Path) -> None:
        proj = tmp_path / "p"
        (proj / "node_modules").mkdir(parents=True)
        (proj / "node_modules" / "BUILD.bazel").write_text("", encoding="utf-8")
        (proj / ".hidden").mkdir()
        (proj / ".hidden" / "SConstruct").write_text("", encoding="utf-8")
        (proj / "legacy").mkdir()
        (proj / "legacy" / "old.uvprojx").write_text("", encoding="utf-8")
        (proj / ".jochwachtignore").write_text("legacy\n", encoding="utf-8")
        (proj / "app.ioc").write_text("", encoding="utf-8")
        assert diagnosis.find_unsupported_markers(proj) == {"stm32cubemx": 1}

    def test_every_marker_is_unread_by_the_scanner_tables(self) -> None:
        # A label in UNSUPPORTED_MARKERS must not name a file the tool reads
        # — otherwise "no reader yet" would be a lie.
        from jochwacht_sbom.analyzer.scanner import BUILD_FILE_PATTERNS

        read_names = set(sbom_scanner._SCANNERS) | {
            Path(p).name for p, _ in BUILD_FILE_PATTERNS
        }
        for label, globs in diagnosis.UNSUPPORTED_MARKERS.items():
            for g in globs:
                assert g not in read_names, (label, g)
                assert not g.endswith(sbom_scanner._MSBUILD_PROJECT_SUFFIXES), (label, g)


class TestCleanRun:
    def test_clean_run_writes_no_diagnosis(self, tmp_path: Path) -> None:
        proj = tmp_path / "clean"
        proj.mkdir()
        (proj / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
        res = CliRunner().invoke(check_cli.main, [str(proj)])
        assert res.exit_code == 0, res.output
        assert not (proj / diagnosis.DIAGNOSIS_FILENAME).exists()
        assert diagnosis.failures() == []
