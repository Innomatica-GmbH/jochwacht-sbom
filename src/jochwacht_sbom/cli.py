"""CLI entry point for jochwacht-sbom (standalone CRA Readiness Check collector).

Usage:
    jochwacht-sbom .                          # read the build, write your SBOM — sends NOTHING
    jochwacht-sbom . --send --email you@example.com   # free CRA report (asks first)
    jochwacht-sbom . --sbom bill.json         # write the SBOM somewhere else
    jochwacht-sbom . --dry-run                # show exactly what a send would contain
    jochwacht-sbom . --output payload.json    # offline / firewall fallback

Exit codes: 0 = success, 1 = error (including a defect in a reader — the
bill is incomplete, a local diagnosis file is written), 2 = no supported
build system found.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from jochwacht_sbom import __version__, diagnosis, env, filenames
from jochwacht_sbom.collector import collect_components
from jochwacht_sbom.core.exceptions import JochwachtError
from jochwacht_sbom.payload import CheckPayload, build_payload
from jochwacht_sbom.sbom_out import (
    SPEC_VERSION,
    SPEC_VERSIONS,
    classify_existing,
    write_cyclonedx,
)
from jochwacht_sbom.upload import DEFAULT_SUBMIT_URL, serialize_payload, upload_payload

_PRIVACY_URL = "https://jochwacht.dev/check-privacy"

console = Console(stderr=True)
_stdout = Console(soft_wrap=True)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="jochwacht-sbom")
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
)
@click.option(
    "--send",
    is_flag=True,
    help="Send the bill of materials to Jochwacht for a free CRA readiness "
    "report (needs --email; asks for confirmation first, shows exactly what "
    "leaves the house). Without this flag NOTHING is transmitted. "
    "Privacy: https://jochwacht.dev/check-privacy",
)
@click.option(
    "--no-send",
    "never_send",
    is_flag=True,
    help="Never ask and never transmit: just read the build and write the "
    "SBOM. For anyone who has decided they will not send.",
)
@click.option(
    "--yes",
    "assume_yes",
    is_flag=True,
    help="Skip the confirmation question (for scripts/CI). Only meaningful "
    "together with --send.",
)
@click.option(
    "--sbom",
    "sbom_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Where to write the CycloneDX SBOM (default: ./sbom.cdx.json). An "
    "existing file is never silently overwritten.",
)
@click.option(
    "--code",
    default="",
    help="Personal one-time code from https://jochwacht.dev/check (optional; "
    "the report goes to the address you registered there).",
)
@click.option("--voucher", default="",
              help="Optional partner / campaign code (tracking only).")
@click.option(
    "--cyclonedx",
    "spec_version",
    type=click.Choice(list(SPEC_VERSIONS)),
    default=SPEC_VERSION,
    show_default=True,
    help="CycloneDX version of the bill written locally. 1.7 is the current "
         "specification (released 2025-10, ECMA-424 2nd edition); 1.6 is the "
         "minimum BSI TR-03183-2 v2.1.0 accepts and what most tooling reads.",
)
@click.option(
    "--lang", type=click.Choice(["de", "en"]), default=None,
    help="Report language. Default: the language of the landing page "
         "your code was issued on (German if undeterminable).",
)
@click.option(
    "--email",
    "contact_email",
    default="",
    help="E-mail address the report is sent to (required with --voucher).",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Print the exact payload that would be uploaded, upload nothing.",
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write the payload to a file instead of uploading (offline fallback).",
)
@click.option(
    "--anonymize",
    is_flag=True,
    help="Replace the project name with a stable hash in the payload.",
)
@click.option(
    "--with-tools",
    is_flag=True,
    help="Additionally use native package-manager CLIs (cargo, go, npm, ...) if installed.",
)
@click.option(
    "--no-declared-metadata",
    "no_declared_metadata",
    is_flag=True,
    help="Do not transmit supplier/license/purl/cpe you declared in "
    "jochwacht-deps.yaml (they are included by default because you wrote "
    "them for SBOM purposes; --dry-run shows the payload either way).",
)
@click.option(
    "--target-env",
    "target_env",
    default="",
    metavar="SPEC",
    help='The environments your product ships into, e.g. '
    '"python=3.10;platform=linux;arch=aarch64,x86_64". A Python lockfile '
    "resolution whose PEP 508 markers are false for all of them is marked "
    "as not shipped instead of being reported as a component you ship. "
    "Without this nothing is evaluated. Keys: python, platform, arch, "
    "system, os, implementation.",
)
@click.option(
    "--url",
    default=DEFAULT_SUBMIT_URL,
    show_default=False,
    help="Override the submit endpoint (testing).",
)
def main(  # noqa: PLR0913 — CLI surface, mirrors documented flags
    path: Path,
    send: bool,
    never_send: bool,
    assume_yes: bool,
    sbom_path: Path | None,
    code: str,
    voucher: str,
    spec_version: str,
    lang: str | None,
    target_env: str,
    contact_email: str,
    dry_run: bool,
    output: Path | None,
    anonymize: bool,
    with_tools: bool,
    no_declared_metadata: bool,
    url: str,
) -> None:
    """Read your build and write your bill of materials — locally.

    Scans PATH (default: current directory) for lockfiles and build files —
    including CONFIGURED builds (CMakeCache.txt) and Yocto/Buildroot build
    output — and writes a CycloneDX SBOM next to you. The default run
    TRANSMITS NOTHING.

    To get a free CRA readiness report, send the bill explicitly with --send
    (you are shown exactly what would leave the house and asked first).
    Never code, never file paths. Privacy: https://jochwacht.dev/check-privacy
    """
    try:
        _run(
            path=path,
            send=send,
            never_send=never_send,
            assume_yes=assume_yes,
            sbom_path=sbom_path,
            spec_version=spec_version,
            code=code,
            voucher=voucher,
            lang=lang,
            target_env=target_env,
            contact_email=contact_email,
            dry_run=dry_run,
            output=output,
            anonymize=anonymize,
            with_tools=with_tools,
            no_declared_metadata=no_declared_metadata,
            url=url,
        )
    except JochwachtError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(exc.exit_code)
    except (click.Abort, click.ClickException, click.exceptions.Exit):
        raise
    except Exception as exc:  # noqa: BLE001 — the tool itself broke outside a reader
        # No traceback on the customer's screen, no silent exit: a local
        # diagnosis file and one sentence asking for a mail. Developers get
        # the plain traceback with JOCHWACHT_SBOM_TRACEBACK=1 (the old
        # JOCHWACHT_ spelling still works, see jochwacht_sbom.env).
        if env.get(diagnosis.TRACEBACK_ENV):
            raise
        where = diagnosis.write_report(diagnosis.crash_report(exc), near=path)
        console.print(
            f"[red]Error:[/red] jochwacht-sbom stopped with an internal error "
            f"({type(exc).__name__}) — a defect in the tool, not in your project.",
            soft_wrap=True,
        )
        _print_diagnosis_request(where, fix="so the defect gets fixed")
        console.print(
            f"[dim]Full traceback: {diagnosis.TRACEBACK_ENV}=1[/dim]", soft_wrap=True,
        )
        sys.exit(1)
    if diagnosis.failures():
        # A reader crashed during the run: the bill was written and shown,
        # but it is incomplete — a CI job must see that (Befund 43 parity:
        # a collector defect is never a green run).
        sys.exit(1)


def _print_diagnosis_request(where: Path, *, fix: str) -> None:
    """The one sentence the order asks for: where the file is, what it
    does not contain, and the request to mail it — by hand, never by us."""
    console.print(
        f"Diagnosis written to {where} — no package names, versions or "
        f"paths; open it and check.",
        soft_wrap=True,
    )
    console.print(
        f"Please mail it to {diagnosis.SUPPORT_ADDRESS} {fix}. Nothing is "
        f"sent automatically.",
        soft_wrap=True,
    )


def _print_reader_failures(
    failures: list[diagnosis.ReaderFailure], where: Path,
) -> None:
    """A reader crashed: say which (by pattern and exception type), say that
    the bill is incomplete, and say whose fault it is — ours."""
    named = ", ".join(
        f"{f.pattern or f.reader or 'run'} ({f.exc_type})" for f in failures
    )
    noun = "reader" if len(failures) == 1 else "readers"
    console.print(
        f"[red]{len(failures)} {noun} failed:[/red] {named} — the bill of "
        f"materials is INCOMPLETE. A defect in jochwacht-sbom, not in your "
        f"project.",
        soft_wrap=True,
    )
    _print_diagnosis_request(where, fix="so the reader gets fixed")


def _print_default_ending(
    written: Path, n_components: int, path_arg: str, *, updated: bool,
) -> None:
    """The end of the default run — output text, never a question (Ivan,
    11.09.2026: "defaultmäßig nicht fragen, sondern als Output-Text")."""
    noun = "component" if n_components == 1 else "components"
    note = " — previous run replaced" if updated else ""
    # soft_wrap: these lines are copied from CI logs and pipes — a command
    # hard-wrapped at 80 columns is a broken command (measured in CI: the
    # long tmp path wrapped the --send line).
    console.print(f"Wrote {written.name} ({n_components} {noun}){note}.", soft_wrap=True)
    console.print("Nothing was transmitted.", soft_wrap=True)
    console.print(
        f"Free CRA readiness report: jochwacht-sbom {path_arg} --send "
        f"--email you@example.com",
        soft_wrap=True,
    )


def _print_leaving_summary(payload: CheckPayload) -> None:
    """Exactly what would leave the house: names + versions, no paths."""
    comps = payload.components
    console.print(
        f"\n[bold]This would be sent[/bold] ({len(comps)} entries — names and "
        f"versions only, no code, no file paths):"
    )
    for c in comps[:15]:
        console.print(f"  {c.name} {c.version or '(no version)'}")
    if len(comps) > 15:
        console.print(f"  … and {len(comps) - 15} more")
    console.print(
        f"  [dim]plus: project label '{payload.project_label}', tool version, "
        f"contact address '{payload.contact_email or '(from your code)'}'[/dim]"
    )


def _run(  # noqa: PLR0913 — mirrors the CLI surface
    *,
    path: Path,
    send: bool = False,
    never_send: bool = False,
    assume_yes: bool = False,
    sbom_path: Path | None = None,
    code: str,
    voucher: str,
    spec_version: str = SPEC_VERSION,
    lang: str | None = None,
    target_env: str = "",
    contact_email: str,
    dry_run: bool,
    output: Path | None,
    anonymize: bool,
    with_tools: bool,
    no_declared_metadata: bool = False,
    url: str,
) -> None:
    """Execute collect → write the SBOM → show → (offer to send).

    Order collector-transparent-machen (Ivan, 09.09.2026): the DEFAULT run
    generates, shows and SAVES — it transmits nothing. Sending is an explicit
    decision: --send, or answering the question after the summary. A code is
    no longer required (Ivan, 09.09.): only an e-mail address, so the report
    can reach the customer; --voucher stays optional for partner tracking.
    """
    # Uploading now happens ONLY on an explicit request. --dry-run and
    # --output keep their meaning (inspect / offline hand-off).
    if never_send and send:
        console.print(
            "[red]Error:[/red] --no-send and --send contradict each other."
        )
        sys.exit(1)
    uploading = send and not dry_run and output is None
    if uploading and code and voucher:
        console.print("[red]Error:[/red] use either --code or --voucher, not both.")
        sys.exit(1)
    if uploading and code:
        # Personal one-time token: the server knows the registered address.
        voucher = code
    if uploading and contact_email and "@" not in contact_email:
        console.print("[red]Error:[/red] --email must be a valid address (report delivery).")
        sys.exit(1)
    # --send is a promise to transmit: check its precondition BEFORE scanning,
    # so the customer is not told "error" only after the work is done. With a
    # personal --code the server knows the address, so that path needs none.
    if uploading and not code and "@" not in (contact_email or ""):
        console.print(
            "[red]Error:[/red] --send needs --email (the address your report "
            "is sent to). Example: jochwacht-sbom . --send --email "
            "you@example.com"
        )
        sys.exit(1)

    console.print(f"[bold]jochwacht-sbom[/bold] {__version__} — scanning {path.resolve().name}/")

    # A file the customer wrote under the former product name is NOT read —
    # the move is complete, without a layer. Saying nothing about it would
    # drop a hand-written declaration in silence, which is the one thing this
    # tool promises never to do.
    for found, needed in filenames.former_spelling_present(path):
        console.print(
            f"[yellow]Note:[/yellow] {found} is present and is [bold]not[/bold] "
            f"read — this tool only reads {needed}. Rename it "
            f"([dim]mv {found} {needed}[/dim]) or its contents are left out of "
            f"the bill."
        )

    diagnosis.reset()
    from jochwacht_sbom.sbom.markers import parse_target_spec

    target_envs, env_warnings = parse_target_spec(target_env)
    for warnung in env_warnings:
        console.print(f"[yellow]Note:[/yellow] {warnung}")
    if target_envs:
        console.print(
            f"[dim]Target environments ({len(target_envs)}): "
            f"{'; '.join(e.label for e in target_envs)}[/dim]"
        )

    components, stats = collect_components(
        path,
        with_tools=with_tools,
        include_declared_metadata=not no_declared_metadata,
        target_envs=target_envs,
    )
    nicht_geliefert = [c for c in components if c.scope == "excluded" and c.scope_reason]
    if nicht_geliefert:
        console.print(
            f"[yellow]{len(nicht_geliefert)} resolution(s) are not shipped into any "
            f"target environment[/yellow] — not counted as yours:"
        )
        # Capped like the send preview: a heavily forked lockfile would
        # otherwise push the rest of the output off the screen.
        sortiert = sorted(nicht_geliefert, key=lambda x: (x.name, x.version))
        for c in sortiert[:15]:
            console.print(f"  [dim]{c.name} {c.version}[/dim]")
        if len(sortiert) > 15:
            console.print(
                f"  [dim]… and {len(sortiert) - 15} more (all of them are in "
                f"the bill with their reason)[/dim]"
            )
    # The diagnosis file lives next to the SBOM (order
    # idee-fehlerrueckmeldung-sammler): the project directory, or the
    # directory of --sbom.
    diag_dir = (sbom_path or (path / "sbom.cdx.json")).parent
    failed_readers = diagnosis.failures()
    if failed_readers:
        # "Werkzeug kaputt": a reader crashed on this tree. The run goes on
        # with what the other readers found, says so in red, writes the
        # local diagnosis file, and ends with exit 1 (see main()).
        where = diagnosis.write_report(
            diagnosis.tool_error_report(
                failed_readers, build_files_scanned=stats.build_files_scanned,
            ),
            near=diag_dir,
        )
        _print_reader_failures(failed_readers, where)
    # "Bausystem nicht unterstützt": markers of build systems we do not read
    # yet, counted by our own labels — a roadmap line, never a defect.
    unread = diagnosis.find_unsupported_markers(path)
    # Conditional alternatives travel MARKED, not as components (Befund 44).
    real = [c for c in components if not c.condition]
    conditional = [c for c in components if c.condition]

    if not real:
        # An empty report is the worst possible answer — but WHY it is empty
        # differs, and telling a CMake customer "no build system found" when
        # their CMakeLists.txt was read is the Befund-42 mistake (describing
        # the tool, not their project). Three cases, three texts.
        if stats.build_files_scanned == 0:
            console.print(
                "[yellow]No supported build system found in this directory."
                "[/yellow]\n"
                "Recognised: Conan, vcpkg, CMake, Cargo, npm/yarn/pnpm, Python "
                "(pip/poetry/uv/pipenv), Go, Maven/Gradle, Alire, Zephyr "
                "(west.yml), FPGA projects (Vivado/Libero/Quartus) — and "
                "Yocto/Buildroot BUILD OUTPUT.\n"
                "For Yocto/Buildroot: run the check in your BUILD directory "
                "(it reads deploy/images/*.manifest resp. "
                "legal-info/manifest.csv), not in the recipe source tree.\n"
                "For proprietary components without a package manager: declare "
                "them once in jochwacht-deps.yaml and re-run.\n"
                "Adjust exclusions via a committed .jochwachtignore."
            )
        elif conditional:
            # Build files WERE read; the default build has no components, but
            # optional backends are available behind a build option.
            names = ", ".join(sorted(c.name for c in conditional)[:4])
            console.print(
                "[yellow]No components in the DEFAULT build.[/yellow]\n"
                f"{len(conditional)} optional backend(s) are available behind "
                f"a build option ({names}): no default build contains them, "
                "and mutually exclusive ones (OpenSSL or LibreSSL) never both "
                "ship.\n"
                "Configure the build once (e.g. `cmake -S . -B build "
                "-DWITH_SSL=ON`) so jochwacht-sbom reads which you actually "
                "use, or declare it in jochwacht-deps.yaml."
            )
        else:
            # Build files read, genuinely nothing — self-contained.
            console.print(
                "[yellow]No external components found.[/yellow]\n"
                f"Read {stats.build_files_scanned} build file(s) "
                f"({', '.join(stats.ecosystems) or 'no package manager'}); "
                "no third-party packages are declared. For a self-contained "
                "library that is plausible.\n"
                "If you link system libraries via `-l` or vendor foreign code "
                "(third_party/, vendor/), declare it in jochwacht-deps.yaml — "
                "or configure the build once (e.g. `cmake -S . -B build`) so "
                "jochwacht-sbom can read build/CMakeCache.txt.\n"
                "Adjust exclusions via a committed .jochwachtignore."
            )
        if stats.build_files_scanned == 0 and unread:
            # Nothing we read, but something we recognise: the file names
            # only which of OUR labels were seen and how often — the
            # customer's file names stay on the customer's disk.
            where = diagnosis.write_report(
                diagnosis.unsupported_build_report(
                    unread, build_files_scanned=stats.build_files_scanned,
                ),
                near=diag_dir,
            )
            console.print(
                f"Build-system markers seen that jochwacht-sbom does not read "
                f"yet: {diagnosis.format_markers(unread)}.",
                soft_wrap=True,
            )
            _print_diagnosis_request(
                where, fix="if you want your build system supported",
            )
        # A read build system that yields nothing (self-contained) or only
        # conditional backends is a VALID result, not a failure — a clean
        # library run in CI must not fail (Befund 44 follow-up). Only "no
        # build system found at all" stays exit 2 — and a crashed reader
        # is an error before anything else.
        if failed_readers:
            sys.exit(1)
        sys.exit(2 if stats.build_files_scanned == 0 else 0)

    console.print(
        f"Found [bold]{len(real)}[/bold] components "
        f"({', '.join(stats.ecosystems) or 'no ecosystem info'}) "
        f"in {stats.build_files_scanned} build files."
    )
    if conditional:
        names = ", ".join(sorted(c.name for c in conditional)[:4])
        console.print(
            f"[dim]{len(conditional)} conditional alternative(s) behind build "
            f"options ({names}) — marked, not counted, not gating. Configure "
            f"the build to resolve which is used.[/dim]"
        )
    for src in stats.build_output_sources:
        console.print(f"[dim]Build output: {src}[/dim]")
    if unread:
        # Read build systems next to unread ones (CMake beside Bazel): say
        # what was not read, so an incomplete bill is never mistaken for a
        # complete one. No file — the run itself is fine.
        console.print(
            f"[dim]Not read (no reader yet): {diagnosis.format_markers(unread)} "
            f"— tell {diagnosis.SUPPORT_ADDRESS} if you need it.[/dim]",
            soft_wrap=True,
        )
    mehrfach = len(real) - len({c.name.lower() for c in real})
    if mehrfach:
        console.print(
            f"[dim]{mehrfach} additional version(s) of already-listed "
            f"packages included — nested second versions are often the "
            f"vulnerable ones.[/dim]"
        )

    # Two different reasons end up as scope="excluded" and they must not be
    # conflated: test/example material and dev tooling on one side, a PEP 508
    # marker that no target environment reaches on the other. Calling the
    # second one "test material" would be a false statement about the
    # customer's project.
    marker_aus = sum(1 for c in components if c.scope == "excluded" and c.scope_reason)
    material_aus = sum(
        1 for c in components if c.scope == "excluded" and not c.scope_reason
    )
    if material_aus:
        console.print(
            f"[dim]{material_aus} component(s) from test/example "
            f"directories or dev tooling marked scope=excluded — listed, "
            f"never gating. Adjust via .jochwachtignore.[/dim]"
        )
    if marker_aus:
        console.print(
            f"[dim]{marker_aus} component(s) marked scope=excluded because no "
            f"target environment reaches them — listed, never gating. The "
            f"reason is in the bill as jochwacht:not-shipped-reason.[/dim]"
        )
    declared = sum(1 for c in components if c.source_type == "declared")
    if declared and not no_declared_metadata:
        console.print(
            f"[dim]{declared} component(s) from jochwacht-deps.yaml include the "
            f"supplier/license/purl/cpe you declared there "
            f"(--no-declared-metadata to withhold, --dry-run to inspect).[/dim]"
        )

    payload = build_payload(
        lang=lang or "",
        # No placeholder (Befund 93a): the field was filled with the literal
        # "DRY-RUN" on EVERY payload — the old comment claimed it was "for
        # dry-run/offline only", but a real --send carried it too. On the
        # server that beat the honest classification, so a paying prospect
        # was filed as CHK-…-DRY-RUN.json and reported as attribution
        # "DRY-RUN" in the support mail that a human forwards by hand.
        # An empty field is the truth: no code was given. The server files
        # it as "no-code".
        voucher=voucher or code or "",
        # With a personal --code the address stays empty — the server fills it
        # from the registration; the placeholder is for dry-run/offline only.
        contact_email=contact_email or ("" if code else "dry-run@localhost"),
        tool_version=__version__,
        project_label=path.resolve().name,
        components=components,
        stats=stats,
        anonymize=anonymize,
    )

    if dry_run:
        console.print("[dim]-- payload that would be uploaded (nothing was sent): --[/dim]")
        _stdout.print_json(payload.model_dump_json())
        console.print(f"[dim]Privacy notice: {_PRIVACY_URL}[/dim]")
        return

    if output is not None:
        output.write_bytes(serialize_payload(payload))
        console.print(
            f"[green]Payload written to {output}.[/green] "
            "Send it to check@innomatica.de to receive your report."
        )
        return

    # --- The default: the customer's own result, written locally ----------
    # Generate → show → save. Nothing is transmitted here (order
    # collector-transparent-machen). An existing SBOM is never silently
    # overwritten — an earlier bill is evidence.
    # The bill belongs to the project that was scanned, not to whatever
    # directory the tool was invoked from (`jochwacht-sbom /path/to/proj`
    # must leave the SBOM in /path/to/proj). --sbom overrides explicitly.
    target = sbom_path or (path / "sbom.cdx.json")
    updated = classify_existing(target) == "own"
    written = write_cyclonedx(
        target,
        components,
        stats,
        project_name=path.resolve().name,
        spec_version=spec_version,
    )
    path_arg = "." if path.resolve() == Path.cwd().resolve() else str(path)

    if not send:
        # The default run ends in text, TTY or not — no question. Sending
        # is a decision the customer makes with --send.
        _print_default_ending(written, len(components), path_arg, updated=updated)
        return

    # --- The send path: show what leaves the house, then ask -------------
    if not assume_yes:
        _print_leaving_summary(payload)
        console.print(f"[dim]Privacy: {_PRIVACY_URL}[/dim]")
        if not click.confirm("Send this to Jochwacht?", default=True):
            console.print("[yellow]Nothing was sent.[/yellow]")
            _print_default_ending(written, len(components), path_arg, updated=updated)
            return
    reference = upload_payload(payload, url=url)
    destination = contact_email or "your registered address"
    console.print(
        f"[green]Sent.[/green] Reference: [bold]{reference}[/bold] — "
        f"your CRA readiness report will be sent to {destination} within 24 hours."
    )


if __name__ == "__main__":
    main()


