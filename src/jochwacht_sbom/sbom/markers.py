"""PEP 508 environment markers against the environments we actually ship.

A Python lockfile holds the resolution for *every* environment the resolver
considered, not for the one that leaves the house. ``uv.lock`` says so
openly: one package entry per resolution, each with its own
``resolution-markers``. Measured on Tepolume (14.10.2026), ``onnx`` appears
twice — 1.22.0 for ``python_full_version < '3.13'`` and 1.19.0 for
``>= '3.13'``. The product ships Python 3.10, so 1.19.0 is never installed;
listing it as shipped produced 16 findings against code that does not exist
in the artefact, one of them CRITICAL.

What this module does: decide, for one package resolution, whether any of
its markers can be true in any environment the user declared as a target.

What it refuses to do: guess. Two rules keep it honest.

**A marker that references an undeclared variable is not evaluated.**
``packaging`` fills missing variables from the *running interpreter*
(verified 14.10.2026: ``Marker("platform_machine == 'x86_64'")`` evaluates
True with only ``python`` declared, on an x86 machine). Using that would
make the bill of materials depend on the build host — the same lockfile
would exclude a package on x86 and keep it on ARM, which breaks the
idempotence rule (same input + same configuration = same output). Such a
resolution counts as shipped, with a warning naming the variable.

**In doubt, shipped.** An unparsable marker, a missing ``packaging``, an
undeclared variable: the resolution stays in the bill. Over-reporting a
component is a nuisance; omitting a shipped one is a false statement about
the product.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

#: Every variable PEP 508 defines. A marker referencing one that the user
#: did not declare cannot be evaluated — see the module docstring.
_PEP508_VARIABLES = frozenset({
    "python_version", "python_full_version", "os_name", "sys_platform",
    "platform_release", "platform_system", "platform_version",
    "platform_machine", "platform_python_implementation",
    "implementation_name", "implementation_version", "extra",
    # packaging 26 also accepts these two. Before they were listed here the
    # guard caught them only because evaluate() raised KeyError and the broad
    # except treated that as undecidable — the right answer for the wrong
    # reason (found in the second review, 14.10.2026).
    "extras", "dependency_groups",
})

#: ``--target-env`` keys and the PEP 508 variables each one fills.
#: ``python`` fills two, because markers use both spellings.
_SPEC_KEYS: dict[str, tuple[str, ...]] = {
    "python": ("python_version", "python_full_version"),
    "platform": ("sys_platform",),
    "arch": ("platform_machine",),
    "system": ("platform_system",),
    "os": ("os_name",),
    "implementation": ("implementation_name", "platform_python_implementation"),
}

#: The values PEP 508 actually sees. A spelling outside these still works
#: (the set is not closed), it only earns a warning — measured 14.10.2026:
#: ``platform=windows`` instead of ``win32`` excluded every component.
_KNOWN_VALUES: dict[str, frozenset[str]] = {
    "platform": frozenset({"linux", "win32", "darwin", "cygwin", "aix", "freebsd"}),
    "arch": frozenset({"x86_64", "aarch64", "arm64", "armv7l", "i686", "s390x", "ppc64le"}),
    "os": frozenset({"posix", "nt"}),
    "system": frozenset({"Linux", "Windows", "Darwin"}),
    "implementation": frozenset({"cpython", "pypy", "CPython", "PyPy"}),
}

_VARIABLE_PATTERN = re.compile(r"\b(" + "|".join(sorted(_PEP508_VARIABLES)) + r")\b")

#: A version literal with three or more components, e.g. ``'3.10.5'``.
#: Both quote styles: the lockfile writes single quotes, packaging's
#: canonical form writes double ones, and this is matched against the
#: canonical text.
_PATCH_LEVEL_LITERAL = re.compile(r"""['"](\d+\.\d+\.\d+[^'"]*)['"]""")


@dataclass(frozen=True)
class TargetEnv:
    """One concrete environment the product is shipped into."""

    #: PEP 508 variable → value. Only what the user declared.
    values: dict[str, str]
    #: How the user wrote it, for messages: ``python=3.10, arch=aarch64``.
    label: str
    #: True when ``python_full_version`` ends in a ``.0`` we appended because
    #: the user wrote ``python=3.10``. A marker comparing a patch level then
    #: cannot be decided — see :func:`_invented_patch_level`.
    python_full_version_invented: bool = False

    def declares(self, variable: str) -> bool:
        return variable in self.values


@dataclass
class Verdict:
    """What to do with one package resolution."""

    #: False only when every marker was evaluated and none can be true.
    shipped: bool
    #: Why — empty when there was nothing to decide.
    reason: str = ""
    #: True when a marker could not be evaluated, so ``shipped`` is a
    #: fallback rather than a measurement. Always logged as a warning.
    undecidable: bool = False
    #: The markers that were examined, for the SBOM property.
    markers: tuple[str, ...] = field(default_factory=tuple)


def parse_target_spec(spec: str) -> tuple[list[TargetEnv], list[str]]:
    """``"python=3.10;platform=linux;arch=aarch64,x86_64"`` → environments.

    Comma-separated values multiply out: the example yields two
    environments. Returns ``([], warnings)`` for an empty spec, which means
    "evaluate nothing" and keeps the old behaviour bit for bit.

    Returns:
        (environments, warnings). An unknown key is a warning, not an
        error — a typo must not silently drop a whole dimension, and it
        must not abort a scan either.
    """
    warnings: list[str] = []
    gewaehlt: dict[str, list[str]] = {}
    for teil in spec.split(";"):
        teil = teil.strip()
        if not teil:
            continue
        if "=" not in teil:
            warnings.append(f"target-env: {teil!r} has no '=' and is ignored")
            continue
        key, _, raw = teil.partition("=")
        key = key.strip().lower()
        if key not in _SPEC_KEYS:
            warnings.append(
                f"target-env: unknown key {key!r} is ignored "
                f"(known: {', '.join(sorted(_SPEC_KEYS))})"
            )
            continue
        werte = [w.strip() for w in raw.split(",") if w.strip()]
        if not werte:
            warnings.append(f"target-env: {key!r} has no value and is ignored")
            continue
        if key in gewaehlt:
            # Silently keeping the last one turned "python=3.10;python=3.13"
            # into a 3.13-only target without a word.
            warnings.append(
                f"target-env: {key!r} given more than once — "
                f"{', '.join(gewaehlt[key])} is replaced by {', '.join(werte)}"
            )
        for wert in werte:
            bekannt = _KNOWN_VALUES.get(key)
            if bekannt and wert not in bekannt:
                # Not an error: sys_platform is open-ended. But "windows"
                # instead of "win32" excludes a whole lockfile in silence,
                # so it must be said out loud.
                warnings.append(
                    f"target-env: {key}={wert!r} is not one of the usual values "
                    f"({', '.join(sorted(bekannt))}) — check the spelling, a "
                    f"wrong value excludes components that do ship"
                )
        gewaehlt[key] = werte

    if not gewaehlt:
        return [], warnings

    schluessel = sorted(gewaehlt)
    umgebungen: list[TargetEnv] = []
    for kombination in _product(*(gewaehlt[k] for k in schluessel)):
        values: dict[str, str] = {}
        for key, wert in zip(schluessel, kombination, strict=True):
            for variable in _SPEC_KEYS[key]:
                values[variable] = _normalise(key, variable, wert)
        label = ", ".join(f"{k}={v}" for k, v in zip(schluessel, kombination, strict=True))
        roh_python = dict(zip(schluessel, kombination, strict=True)).get("python", "")
        umgebungen.append(TargetEnv(
            values=values, label=label,
            python_full_version_invented=bool(roh_python) and roh_python.count(".") < 2,
        ))
    return umgebungen, warnings


def _product(*listen: list[str]) -> list[tuple[str, ...]]:
    """Cartesian product, spelled out to keep the import list short."""
    ergebnis: list[tuple[str, ...]] = [()]
    for liste in listen:
        ergebnis = [vorher + (wert,) for vorher in ergebnis for wert in liste]
    return ergebnis


def _normalise(key: str, variable: str, wert: str) -> str:
    """The value as PEP 508 expects it for *variable*."""
    if key != "python":
        return wert
    teile = wert.split(".")
    if variable == "python_version":
        return ".".join(teile[:2])
    # python_full_version wants three components. A user who writes
    # "3.10" gets "3.10.0"; TargetEnv records that we made it up.
    while len(teile) < 3:
        teile.append("0")
    return ".".join(teile)


def evaluate(markers: list[str] | tuple[str, ...], envs: list[TargetEnv]) -> Verdict:
    """Is a resolution carrying *markers* shipped into any of *envs*?

    Two passes, and the order matters. **First** every marker is tried for a
    definite hit; only if none hits does an undecidable one count. A
    resolution with ``["platform_release == '5.15.0'", "python_full_version
    < '3.13'"]`` is demonstrably shipped for Python 3.10 — stopping at the
    first marker we cannot read would have buried that behind a warning
    (found in review, 14.10.2026).

    Args:
        markers: the resolution's markers. Empty means "no condition", so
            the resolution is shipped — the common case and the reason an
            unmarked lockfile behaves exactly as before.
        envs: the declared target environments. Empty means the feature is
            off: everything is shipped, nothing is evaluated.
    """
    markers = tuple(m for m in markers if str(m).strip())
    if not envs or not markers:
        return Verdict(shipped=True, markers=markers)

    try:
        from packaging.markers import InvalidMarker, Marker
    except ImportError:  # pragma: no cover - packaging is a declared dependency
        return Verdict(
            shipped=True, undecidable=True, markers=markers,
            reason="packaging is not installed — markers were not evaluated",
        )

    unentscheidbar: list[str] = []
    for roh in markers:
        try:
            marker = Marker(roh)
        except InvalidMarker as exc:
            unentscheidbar.append(f"marker {roh!r} is not valid PEP 508 ({exc})")
            continue

        # Canonical text, not the raw one: packaging accepts the legacy
        # spellings `platform.machine`, `os.name`, `sys.platform`,
        # `python_implementation` … and normalises them. Searching the raw
        # string missed every one of those, so the guard below did not fire
        # and packaging silently answered from the BUILD HOST — the exact
        # idempotence break this module exists to prevent (found in review).
        kanonisch = str(marker)
        verwendet = set(_VARIABLE_PATTERN.findall(kanonisch))

        getroffen = False
        for env in envs:
            # `continue`, not `break`: another target environment may still
            # decide this marker outright. With --target-env
            # "python=3.10,3.11.5" a marker needing a patch level is
            # undecidable for the first and a clear hit for the second
            # (found in the second review, 14.10.2026).
            fehlend = sorted(v for v in verwendet if not env.declares(v))
            if fehlend:
                unentscheidbar.append(
                    f"marker needs {', '.join(fehlend)}, which the target "
                    f"environment does not declare"
                )
                continue
            if _invented_patch_level(kanonisch, env):
                unentscheidbar.append(
                    f"marker {roh!r} compares a Python patch level while the "
                    f"target gives major.minor only ({env.label}) — give "
                    f"python=X.Y.Z to decide this"
                )
                continue
            try:
                if marker.evaluate(dict(env.values)):
                    getroffen = True
                    continue
            except Exception as exc:  # noqa: BLE001 - packaging raises several types
                unentscheidbar.append(f"marker {roh!r} could not be evaluated ({exc})")
                break
        if getroffen:
            return Verdict(shipped=True, markers=markers)

    if unentscheidbar:
        return Verdict(
            shipped=True, undecidable=True, markers=markers,
            reason=unentscheidbar[0] + " — counted as shipped",
        )

    ziele = "; ".join(e.label for e in envs)
    return Verdict(
        shipped=False, markers=markers,
        reason=f"no marker is true for any target environment ({ziele})",
    )


def _invented_patch_level(kanonisch: str, env: TargetEnv) -> bool:
    """True when the marker compares a patch level we had to make up.

    ``python=3.10`` becomes ``python_full_version == "3.10.0"``. Against
    ``>= '3.14'`` that is exact; against ``>= '3.10.5'`` the ``.0`` is a
    guess, and guessing is what this module refuses to do.
    """
    if not env.python_full_version_invented:
        return False
    if "python_full_version" not in kanonisch:
        return False
    return bool(_PATCH_LEVEL_LITERAL.search(kanonisch))
