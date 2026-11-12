"""0.8.5 — genau zwei Fixes (Befunde 93a und 81 im Zwilling).

93a: Der Client schrieb den wörtlichen Platzhalter "DRY-RUN" in JEDE Nutzlast,
auch beim echten --send. Serverseitig schlug das die ehrliche Einstufung, und
die Einsendung eines zahlenden Interessenten lag als CHK-…-DRY-RUN.json im
Posteingang — in einer Kette, in der jeder Bericht VON HAND weitergeleitet wird.

81: Der Zwilling stempelte nur Testmaterial ("excluded"); alles andere blieb
ohne Scope. Damit konnte der Kundenbericht Produkt und Testmaterial nicht
trennen — genau die Unterscheidung, die der Gratis-Check liefern soll.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from jochwacht_sbom.cli import main
from jochwacht_sbom.sbom.scanner import scan_directory_recursive


def _project(tmp_path: Path) -> Path:
    p = tmp_path / "proj"
    p.mkdir()
    (p / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.10)\n"
        "project(proj)\nfind_package(OpenSSL REQUIRED)\n",
        encoding="utf-8",
    )
    tests = p / "tests"
    tests.mkdir()
    (tests / "requirements.txt").write_text("pytest==7.0.0\n", encoding="utf-8")
    return p


class TestNoPlaceholderVoucher:
    """93a — ein leeres Feld ist die Wahrheit: es wurde kein Code angegeben."""

    def test_the_written_payload_carries_no_placeholder(self, tmp_path: Path) -> None:
        # The payload is no longer sent (--send sends the SBOM since
        # 12.11.2026); it is still written with --output.
        proj = _project(tmp_path)
        out = tmp_path / "payload.json"
        res = CliRunner().invoke(main, [str(proj), "--output", str(out)])
        assert res.exit_code == 0, res.output
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["voucher"] == "", payload["voucher"]

    def test_a_voucher_still_reaches_the_written_payload(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        out = tmp_path / "payload.json"
        res = CliRunner().invoke(main, [str(proj), "--output", str(out),
                                        "--voucher", "PARTNER-2026"])
        assert res.exit_code == 0, res.output
        assert json.loads(out.read_text(encoding="utf-8"))["voucher"] == "PARTNER-2026"

    def test_the_dry_run_output_carries_no_placeholder_either(
        self, tmp_path: Path,
    ) -> None:
        proj = _project(tmp_path)
        res = CliRunner().invoke(
            main, [str(proj), "--send", "--email", "a@b.de", "--yes",
                   "--dry-run"],
        )
        assert res.exit_code == 0, res.output
        assert '"voucher": "DRY-RUN"' not in res.output


class TestEveryComponentCarriesAScope:
    """81 — Produkt und Testmaterial müssen unterscheidbar sein."""

    def test_the_scanner_stamps_production_components(
        self, tmp_path: Path,
    ) -> None:
        deps = scan_directory_recursive(_project(tmp_path))
        by_name = {d.name: d.scope for d in deps}
        assert by_name, deps
        assert all(s for s in by_name.values()), by_name
        assert by_name.get("pytest") == "excluded"      # unverändert

    def test_the_payload_carries_the_scope(self, tmp_path: Path) -> None:
        # Abnahme des Auftrags: das Testmaterial ist in der Einsendung
        # ausgewiesen, damit der Bericht es trennen kann.
        proj = _project(tmp_path)
        out = tmp_path / "payload.json"
        res = CliRunner().invoke(main, [str(proj), "--output", str(out)])
        assert res.exit_code == 0, res.output
        comps = json.loads(out.read_text(encoding="utf-8"))["components"]
        assert comps
        assert all(c.get("scope") for c in comps), [(c["name"], c.get("scope")) for c in comps]

    def test_the_written_sbom_separates_product_from_test_material(
        self, tmp_path: Path,
    ) -> None:
        proj = _project(tmp_path)
        res = CliRunner().invoke(main, [str(proj)])
        assert res.exit_code == 0, res.output
        doc = json.loads(
            (proj / "sbom.cdx.json").read_text(encoding="utf-8"),
        )
        scopes = {c["name"]: c.get("scope") for c in doc["components"]}
        assert scopes, doc
        assert all(scopes.values()), scopes
        assert "excluded" in scopes.values()


class TestNoComponentLeavesWithoutAScope:
    """Befund 81 Nachtrag (0.8.6) — die Invariante über ALLE Erkennungswege.

    Mein 0.8.5-Test war grün und trotzdem falsch: sein Fixture traf nur den
    Lockfile-Weg (OpenSSL über pkg-config aufgelöst). Am echten libwebsockets
    blieben 15 von 30 Komponenten ohne Scope — 12 aus dem Regex-CMake-Weg
    (Tier 4, nicht auflösbar), 3 bedingte hinter einer Bauoption. Beide Wege
    entstehen in collector.py, nicht im Scanner, und beide schrieb ich mit
    leerem Scope.

    Dieses Fixture erzwingt alle drei Wege. "optional" ist die belegbare
    Aussage: aus einer Baudatei gelesen, ohne aufgelösten Bau nicht
    entscheidbar, ob es mitgeht — weder "required" noch "excluded" wären
    belegt.
    """

    @staticmethod
    def _three_paths(tmp_path: Path) -> Path:
        p = tmp_path / "proj"
        p.mkdir()
        (p / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.10)\n"
            "project(proj)\n"
            "find_package(OpenSSL REQUIRED)\n"          # aufloesbar -> required
            "find_package(Miniz)\n"                     # Regex, Tier 4 -> ?
            "find_package(rav1e)\n"                     # Regex, Tier 4 -> ?
            "option(WITH_ALSA \"alsa\" OFF)\n"
            "if(WITH_ALSA)\n"
            "  find_package(ALSA REQUIRED)\n"           # bedingt -> ?
            "endif()\n",
            encoding="utf-8",
        )
        tests = p / "tests"
        tests.mkdir()
        (tests / "requirements.txt").write_text("pytest==7.0.0\n", encoding="utf-8")
        return p

    def _components(self, tmp_path: Path) -> list:
        from jochwacht_sbom.payload import CheckPayload

        proj = self._three_paths(tmp_path)
        out = tmp_path / "payload.json"
        res = CliRunner().invoke(main, [str(proj), "--output", str(out)])
        assert res.exit_code == 0, res.output
        return list(CheckPayload.model_validate_json(out.read_text(encoding="utf-8")).components)

    def test_a_tier4_regex_hit_without_condition_becomes_optional(
        self, tmp_path: Path,
    ) -> None:
        # Der Weg, den kein Fixture-Zufall trifft: run_pipeline liefert einen
        # Regex-Fund (Tier 4) ohne Bedingung — an libwebsockets 12 Stueck
        # (alsa, gstreamer, mbedtls, opus, sqlite3, wolfssl, …). Direkt
        # injiziert statt ueber Parser-Heuristik, damit der Test genau den
        # Code trifft, der in 0.8.5 den leeren Scope schrieb.
        from types import SimpleNamespace

        from jochwacht_sbom.collector import collect_components
        proj = self._three_paths(tmp_path)
        fake = SimpleNamespace(
            name="wolfssl", version="", ecosystem="cmake",
            detection_method="regex-cmake", tier=4, confidence=0.7,
            source_file="lib/tls/CMakeLists.txt", context="",
        )
        with patch("jochwacht_sbom.collector.run_pipeline",
                   return_value=([fake], [], [])):
            comps, _stats = collect_components(proj)
        by_name = {c.name.lower(): c for c in comps}
        assert "wolfssl" in by_name, [c.name for c in comps]
        assert by_name["wolfssl"].source_type == "regex-cmake"
        assert by_name["wolfssl"].scope == "optional", by_name["wolfssl"]

    def test_no_component_has_an_empty_scope(self, tmp_path: Path) -> None:
        comps = self._components(tmp_path)
        unstamped = [(c.name, c.source_type) for c in comps if not c.scope]
        assert not unstamped, unstamped

    def test_a_conditional_hit_is_optional_not_required(
        self, tmp_path: Path,
    ) -> None:
        # ALSA steht hinter einer Bauoption, die standardmaessig aus ist:
        # kein Beleg, dass es mitgeht -> keine Behauptung. (Miniz/rav1e
        # laufen im Fixture ueber den Scanner-Weg und tragen dort die
        # Suite-Regel "required" — an libwebsockets kommen sie ueber den
        # Regex-Weg, den der Test oben direkt abdeckt.)
        comps = self._components(tmp_path)
        by_name = {c.name.lower(): c.scope for c in comps}
        assert by_name.get("alsa") == "optional", by_name
        assert by_name.get("pytest") == "excluded"
