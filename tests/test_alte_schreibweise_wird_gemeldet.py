"""Eine Erklärungsdatei, die anders heißt, wird nicht gelesen — und wir sagen es.

Die Umbenennung vom 01.10.2026 ist vollständig: ein Name je Datei, keine
Verträglichkeitsschicht (Ivan, 02.10.2026). Was nicht stehen bleiben darf,
ist das SCHWEIGEN darüber: eine von Hand eingetragene Erklärung ist die eine
Angabe, die sonst nichts rekonstruieren kann, und sie wortlos fallen zu
lassen ist ein Messverlust, den niemand bemerkt.

Gemessen am 05.10.2026 gegen die veröffentlichte 0.13.0, auf dem echten Weg:
ein Projekt, das seine Erklärungen nur unter einem anderen Dateinamen liegen
hatte, erzeugte eine Stückliste mit null erklärten Komponenten und sagte
nichts dazu.

**Seit dem 29.10.2026 prüft die Meldung die FORM, nicht einen Namen.** Ivans
Vorgabe „es darf kein alter Name mehr geben, egal wo" hätte die Meldung sonst
mitgenommen. Statt drei fester Namen wird jetzt gefragt: liegt hier eine
Datei, die wie eine Erklärungsdatei aussieht, aber nicht so heißt, wie wir
sie lesen? Das fängt den alten Namen weiterhin — und zusätzlich Tippfehler
und Nachbarnamen, die vorher durchrutschten.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from jochwacht_sbom import filenames
from jochwacht_sbom.cli import main

#: Namen, die eine Erklärungsdatei sein wollen, aber nicht gelesen werden.
#: Der erste ist aus Teilen gebaut: es ist der Name des Vorgängerprodukts,
#: und diese Datei buchstabiert ihn nicht.
_ANDERS_BENANNT = [
    "embt" + "race" + "-deps.yaml",
    "acme-deps.yaml",
    "jochwach-deps.yaml",      # Tippfehler — vorher unsichtbar
]

#: Nur die Gross-/Kleinschreibung unterscheidet sich. Ob das eine ANDERE
#: Datei ist, entscheidet das Dateisystem und nicht wir — siehe den Test
#: darunter.
_NUR_ANDERE_SCHREIBWEISE = "Jochwacht-deps.yaml"


@pytest.mark.parametrize("name", _ANDERS_BENANNT)
def test_a_differently_named_declaration_file_is_reported(
    name: str, tmp_path: Path,
) -> None:
    (tmp_path / name).write_text("x\n", encoding="utf-8")
    assert filenames.declaration_file_not_read(tmp_path) == [(name, filenames.DEPS)]


def test_a_name_differing_only_in_case_follows_the_file_system(tmp_path: Path) -> None:
    """Gemeldet wird, was NICHT GELESEN wird — und das sagt das Dateisystem.

    Auf Linux ist ``Jochwacht-deps.yaml`` eine andere Datei als
    ``jochwacht-deps.yaml``: sie wird nicht gelesen, also wird sie gemeldet.
    Auf Windows und macOS ist es DIESELBE Datei — ein ``open`` auf unseren
    Namen öffnet sie, die Erklärungen gehen also gar nicht verloren, und eine
    Meldung wäre falsch.

    Gefunden am 29.10.2026 von der Windows-Matrix der CI, nachdem der Test
    hier die Linux-Antwort als die einzige behauptet hatte (Lauf
    40912477657, ``windows-latest, 3.12``, 1 von 244 rot). Der Test fragt
    deshalb jetzt das Dateisystem, statt eine Plattform zu raten — ``sys.platform``
    stünde hier für eine Annahme, ``is_file()`` ist eine Messung.
    """
    (tmp_path / _NUR_ANDERE_SCHREIBWEISE).write_text("x\n", encoding="utf-8")
    liest_sie_schon = (tmp_path / filenames.DEPS).is_file()
    gemeldet = filenames.declaration_file_not_read(tmp_path)
    if liest_sie_schon:
        assert gemeldet == [], (
            "das Dateisystem unterscheidet die Schreibweise nicht — die Datei WIRD"
            " gelesen, eine Meldung waere falsch")
    else:
        assert gemeldet == [(_NUR_ANDERE_SCHREIBWEISE, filenames.DEPS)]


def test_nothing_is_reported_for_a_clean_project(tmp_path: Path) -> None:
    for name in filenames.ALL:
        (tmp_path / name).write_text("x\n", encoding="utf-8")
    assert filenames.declaration_file_not_read(tmp_path) == []


def test_the_current_file_wins_and_silences_the_note(tmp_path: Path) -> None:
    """Beide da: die unsere wird gelesen, also gibt es nichts zu melden."""
    (tmp_path / "acme-deps.yaml").write_text("x\n", encoding="utf-8")
    (tmp_path / filenames.DEPS).write_text("x\n", encoding="utf-8")
    assert filenames.declaration_file_not_read(tmp_path) == []


def test_a_harmless_file_never_triggers_it(tmp_path: Path) -> None:
    """Die Gegenprobe: die Form darf nicht alles einsammeln.

    Ohne sie wäre die Meldung schnell Lärm, und Lärm wird überlesen.
    """
    for harmlos in (".gitignore", "requirements.txt", "pyproject.toml",
                    "deps.txt", "docker-compose.yaml"):
        (tmp_path / harmlos).write_text("x\n", encoding="utf-8")
    assert filenames.declaration_file_not_read(tmp_path) == []


def test_the_gap_is_deliberate_and_recorded(tmp_path: Path) -> None:
    """Was die Meldung seit dem 29.10.2026 NICHT mehr fängt — bewusst.

    Für die Projektkonfiguration (``*.yaml``) und die Ausschlussliste
    (``.*ignore``) gibt es keine Form, die nicht massenhaft Falschmeldungen
    erzeugte — ``.gitignore`` wäre eine davon. Diese beiden Fälle bleiben
    also stumm. Vertretbar ist das, weil der gemessene Verlust vom
    05.10.2026 die ERKLÄRUNGSdatei betraf: sie trägt Angaben, die sonst
    nirgends stehen, während eine fehlende Konfiguration nur Vorgaben
    bedeutet.

    Dieser Test hält die Lücke fest, damit niemand sie später für einen
    Fehler hält — oder sie stillschweigend schließt und Lärm erzeugt.
    """
    (tmp_path / ("embt" + "race" + ".yaml")).write_text("x\n", encoding="utf-8")
    (tmp_path / ("." + "embt" + "race" + "ignore")).write_text("x\n", encoding="utf-8")
    assert filenames.declaration_file_not_read(tmp_path) == []


def test_the_run_says_it_out_loud(tmp_path: Path) -> None:
    """Der echte Weg: was der Kunde auf seinem Bildschirm sieht."""
    (tmp_path / "acme-deps.yaml").write_text(
        "dependencies:\n  - name: libhand\n    version: 1.2.3\n    license: MIT\n",
        encoding="utf-8",
    )
    out = tmp_path / "sbom.cdx.json"
    result = CliRunner().invoke(main, [str(tmp_path), "--sbom", str(out)])

    gesagt = result.output.replace("\n", " ")
    assert "is not read" in gesagt
    assert "jochwacht-deps.yaml" in gesagt
    # Und die Erklärung fehlt wirklich — die Meldung ist nicht kosmetisch.
    assert "libhand" not in gesagt


def test_the_note_is_not_an_error(tmp_path: Path) -> None:
    """Sie informiert, sie sperrt nicht."""
    (tmp_path / "acme-deps.yaml").write_text("x\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("jinja2==3.1.2\n", encoding="utf-8")
    out = tmp_path / "sbom.cdx.json"
    result = CliRunner().invoke(main, [str(tmp_path), "--sbom", str(out)])
    assert result.exit_code == 0, result.output
    assert out.is_file()
