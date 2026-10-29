"""Files the customer writes, in one place.

``jochwacht.yaml`` (project configuration, written by the suite),
``jochwacht-deps.yaml`` (dependencies declared by hand) and
``.jochwachtignore`` (paths to leave out of a scan).

Mirror of ``jochwacht/core/filenames.py`` in the suite: both halves read
the same files, and a disagreement would mean one honours a file the other
ignores.
"""

from __future__ import annotations

from pathlib import Path

#: Project configuration — written by the suite, only read here.
CONFIG = "jochwacht.yaml"

#: Dependencies the customer declares by hand.
DEPS = "jochwacht-deps.yaml"

#: Paths to leave out of the scan.
IGNORE = ".jochwachtignore"

#: Every name the customer may write, for guards and listings.
ALL: tuple[str, ...] = (CONFIG, DEPS, IGNORE)


def both(name: str) -> tuple[str, ...]:
    """The spellings accepted for *name* — one each since 01.10.2026."""
    return (name,)


#: Eine von Hand erklaerte Abhaengigkeit, die stillschweigend unter den Tisch
#: faellt, ist ein Messverlust, den niemand bemerkt — und "nichts passiert
#: still" ist das Versprechen dieses Werkzeugs. Gemessen am 05.10.2026: ein
#: Projekt, das seine Erklaerungen nur unter einem anderen Dateinamen liegen
#: hatte, erzeugte eine Stueckliste mit null erklaerten Komponenten und ohne
#: ein Wort dazu.
#:
#: Bis zum 29.10.2026 wurde dafuer auf drei feste Namen geprueft — die des
#: vorherigen Produkts. Seit Ivans Entscheidung ("es darf kein alter Name
#: mehr geben, egal wo") nennt diese Pruefung keinen Namen mehr, sondern
#: beschreibt die FORM: eine Datei, die wie eine Erklaerungsdatei aussieht,
#: aber nicht so heisst, wie wir sie lesen.
#:
#: **Grenze, die man kennen muss.** Verallgemeinern laesst sich nur die
#: Erklaerungsdatei. Fuer die Projektkonfiguration (``*.yaml``) und die
#: Ausschlussliste (``.*ignore``) gibt es keine Form, die nicht massenhaft
#: Falschmeldungen erzeugte — ``.gitignore`` waere eine davon. Die beiden
#: Faelle werden also NICHT mehr gemeldet. Das ist vertretbar, weil der
#: gemessene Verlust vom 05.10.2026 die ERKLAERUNGSdatei betraf: sie traegt
#: Angaben, die sonst nirgends stehen, waehrend eine fehlende Konfiguration
#: nur Vorgaben bedeutet.
_DEKLARATIONS_MUSTER = "*-deps.yaml"


def declaration_file_not_read(directory: Path) -> list[tuple[str, str]]:
    """``[(Datei die da ist, Name den sie braucht)]`` fuer Erklaerungsdateien,
    die wir NICHT lesen, weil sie anders heissen.

    Leer, wenn das Verzeichnis keine solche traegt — der Normalfall.
    """
    if (directory / DEPS).is_file():
        return []
    gefunden = sorted(
        p.name for p in directory.glob(_DEKLARATIONS_MUSTER) if p.is_file()
    )
    return [(name, DEPS) for name in gefunden]


def find(directory: Path, name: str) -> Path | None:
    """The file in *directory*, or None when it is not there."""
    path = directory / name
    return path if path.is_file() else None
