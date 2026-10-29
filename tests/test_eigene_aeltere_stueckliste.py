"""Welche Stueckliste gilt als UNSERE — und welche nicht mehr.

``write_cyclonedx`` weigert sich, eine FREMDE Datei zu ueberschreiben: das
ist der Nachweis von jemand anderem. Entschieden wird am Stempel in
``metadata.tools``.

**Seit dem 29.10.2026 steht dort genau ein Name.** Ivans Entscheidung ("nein,
es gibt keine kunden") hat die Stempel der Vorgaengerfassungen entfernt. Die
Folge haelt dieser Test fest, statt sie zu verschweigen: eine Stueckliste,
die eine Fassung vor 0.12.0 geschrieben hat, gilt jetzt als fremd und wird
nicht ueberschrieben. Der Nutzer bekommt einen Fehler mit Ausweg
(``--sbom PATH``), keine stille Ueberraschung.

Die Geschichte davor gehoert bewahrt, weil sie zweimal zugeschlagen hat: am
01.10. und am 02.10.2026 nahm eine Umbenennung des PAKETS den historischen
Stempel mit — beim zweiten Mal samt dem Kommentar, der vor dem ersten Mal
gewarnt hatte. Gemessen am 05.10.2026 gegen die veroeffentlichte 0.13.0 hiess
das fuer den Nutzer: sein eigenes Werkzeug nannte seine eigene Datei fremd,
ohne dass jemand das entschieden haette. Heute ist es entschieden — das ist
der Unterschied.

Diese Datei buchstabiert den alten Namen nicht mehr, sondern setzt ihn aus
Teilen zusammen: ein Suchen-und-Ersetzen kann sie damit nicht still
umdrehen.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from jochwacht_sbom.core.exceptions import JochwachtError
from jochwacht_sbom.sbom_out import OWN_TOOL_NAMES, classify_existing

#: Der Stempel, den dieses Werkzeug heute schreibt — und nur der.
_STAMPS = {
    "jochwacht-sbom": "since 0.12.0",
}

#: Aus Teilen gebaut: der Stempel der Fassungen 0.9.0 bis 0.11.1. Er gilt
#: seit dem 29.10.2026 NICHT mehr als unserer, und genau das wird unten
#: geprueft.
_VORGAENGER = "embt" + "race" + "-sbom"


def _bill(tool: str) -> str:
    return json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"tools": [
            {"vendor": "Innomatica GmbH", "name": tool, "version": "0.11.1"},
        ]},
        "components": [],
    })


def test_the_set_holds_every_name_this_tool_ever_signed_with() -> None:
    assert frozenset(_STAMPS) == OWN_TOOL_NAMES, (
        "a stamp was dropped — a bill from an older release would be refused "
        "as foreign"
    )


@pytest.mark.parametrize("tool", sorted(_STAMPS))
def test_a_bill_from_any_of_our_releases_is_own(tool: str, tmp_path: Path) -> None:
    target = tmp_path / "sbom.cdx.json"
    target.write_text(_bill(tool), encoding="utf-8")
    assert classify_existing(target) == "own"


@pytest.mark.parametrize("tool", ["syft", "trivy", "cdxgen", "Jochwacht-SBOM"])
def test_somebody_elses_bill_stays_foreign(tool: str, tmp_path: Path) -> None:
    """Including a near-miss spelling: the stamp is compared exactly."""
    target = tmp_path / "sbom.cdx.json"
    target.write_text(_bill(tool), encoding="utf-8")
    assert classify_existing(target) == "foreign"


def test_an_older_own_bill_is_now_refused_as_foreign(tmp_path: Path) -> None:
    """Die gewollte Folge von Ivans Entscheidung, am echten Weg gemessen.

    Bis zum 29.10.2026 wurde eine solche Datei ueberschrieben, weil sie als
    unsere galt. Jetzt nicht mehr — und das soll AUFFALLEN, nicht stillschweigen:
    der Nutzer bekommt einen Fehler, der den Ausweg nennt.
    """
    from jochwacht_sbom.collector import CheckStats
    from jochwacht_sbom.sbom_out import write_cyclonedx

    target = tmp_path / "sbom.cdx.json"
    inhalt = _bill(_VORGAENGER)
    target.write_text(inhalt, encoding="utf-8")

    assert classify_existing(target) == "foreign"
    with pytest.raises(JochwachtError) as fehler:
        write_cyclonedx(target, [], CheckStats(), project_name="demo")
    assert "--sbom" in str(fehler.value), "eine Abweisung ohne Ausweg ist eine Sackgasse"
    # Und die Datei bleibt unberuehrt — sie wird nicht halb ueberschrieben.
    assert target.read_text(encoding="utf-8") == inhalt


def test_a_foreign_bill_is_still_refused(tmp_path: Path) -> None:
    """The protection itself must stay — this is somebody's evidence."""
    from jochwacht_sbom.collector import CheckStats
    from jochwacht_sbom.sbom_out import write_cyclonedx

    target = tmp_path / "sbom.cdx.json"
    target.write_text(_bill("syft"), encoding="utf-8")
    with pytest.raises(JochwachtError):
        write_cyclonedx(target, [], CheckStats(), project_name="demo")


def test_both_stamp_forms_are_read(tmp_path: Path) -> None:
    """Older bills carry ``metadata.tools`` as a LIST, newer as an object.

    A classifier that knows only one form calls half our own history foreign.
    """
    # Der NAME ist hier nebensaechlich — geprueft wird die FORM. Bis zum
    # 29.10.2026 stand hier der Stempel einer Vorgaengerfassung; der gilt
    # nicht mehr als unserer, also waere der Test sonst aus dem falschen
    # Grund rot geworden.
    stamp = {"vendor": "Innomatica GmbH", "name": "jochwacht-sbom",
             "version": "0.12.0"}
    for tools in ({"components": [stamp]}, [stamp]):
        target = tmp_path / "sbom.cdx.json"
        target.write_text(json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"tools": tools}, "components": [],
        }), encoding="utf-8")
        assert classify_existing(target) == "own", tools
