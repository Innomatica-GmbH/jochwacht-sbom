"""Structured logging with Rich console output.

Usage::

    from jochwacht_sbom.core.log import console, get_logger

    logger = get_logger(__name__)
    logger.info("Processing artifact %s", name)
    console.print("[green]Done.[/green]")
"""

from __future__ import annotations

import logging
import re
import sys
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.errors import MarkupError
from rich.logging import RichHandler
from rich.markup import escape
from rich.segment import Segment

from jochwacht_sbom.core.safe_text import strip_unsafe

if TYPE_CHECKING:
    from collections.abc import Iterable

    from rich.console import ConsoleOptions, RenderableType
    from rich.text import Text


#: A Rich link tag not already escaped.
_LINK_TAG = re.compile(r"(?<!\\)\[link\b")


def fg(value: object) -> str:
    """A foreign value (a name from a bill, an advisory's text, a path)
    ready to go into console markup: printed as it is, never as markup.
    Use it for every such value in an f-string that a console prints."""
    return escape(str(value))


def _escape_unmatched_closers(text: str) -> str:
    """*text* with every closing tag that closes nothing escaped — the tags
    that make Rich raise MarkupError ("[/bold]" without "[bold]", "[/]"
    with nothing open). Matching tags, ours included, stay markup."""
    from rich.markup import RE_TAGS

    out: list[str] = []
    stack: list[str] = []
    pos = 0
    for match in RE_TAGS.finditer(text):
        escapes, tag = match.group(2), match.group(3)
        out.append(text[pos:match.start()])
        pos = match.end()
        whole = match.group(0)
        if escapes and len(escapes) % 2:       # already escaped: literal
            out.append(whole)
            continue
        if not tag.startswith("/"):
            stack.append(tag.split("=", 1)[0].strip())
            out.append(whole)
            continue
        name = tag[1:].strip()
        if (not name and stack) or (name and name in stack):
            if name:
                while stack and stack.pop() != name:
                    pass
            else:
                stack.pop()
            out.append(whole)
        else:
            out.append(whole[:len(escapes)] + "\\" + whole[len(escapes):])
    out.append(text[pos:])
    return "".join(out)


class SafeConsole(Console):
    """A Rich console that never passes control text from outside through.

    Names, versions and licenses of a supplier's bill reach the terminal in
    many places; one ESC sequence among them could steer the terminal or
    forge lines (measured raw ESC, U+202E, U+2028, U+009B
    on the console of ``sbom vuln`` and ``comply audit``). Cleaning happens
    on the rendered segments: text segments lose control, format and
    separator characters (``core.safe_text``); Rich's own control segments
    and the styles it renders afterwards are left alone, so colours stay.
    """

    def render_str(self, text: str, **kwargs: Any) -> Text:
        """Markup that a foreign value could inject is closed here for every
        caller: a ``[link=…]`` tag is never a link (our own
        output has none), and markup that does not parse — a supplier's
        component named "[/bold]" — is printed as text instead of stopping
        the run with a MarkupError. Styling a foreign value ("[bold red]")
        can only be prevented where it is inserted: :func:`fg`."""
        if kwargs.get("markup") is False or (kwargs.get("markup") is None and not self._markup):
            return super().render_str(text, **kwargs)
        text = _LINK_TAG.sub(r"\\[link", text)
        try:
            return super().render_str(text, **kwargs)
        except MarkupError:
            pass
        try:
            return super().render_str(_escape_unmatched_closers(text), **kwargs)
        except MarkupError:
            return super().render_str(text, **{**kwargs, "markup": False})

    def render(
        self, renderable: RenderableType, options: ConsoleOptions | None = None,
    ) -> Iterable[Segment]:
        for segment in super().render(renderable, options):
            if segment.control or not segment.text:
                yield segment
                continue
            cleaned = strip_unsafe(segment.text)
            yield segment if cleaned == segment.text else Segment(
                cleaned, segment.style, segment.control)


# Shared console instances — use `console` for normal output,
# `error_console` for errors/warnings.
console = SafeConsole(stderr=False)
error_console = SafeConsole(stderr=True)

_LOG_FORMAT = "%(message)s"
_configured = False


def setup_logging(*, verbosity: int = 0, json_mode: bool = False) -> None:
    """Configure the root jochwacht logger.

    Args:
        verbosity: 0 = WARNING, 1 = INFO, 2+ = DEBUG.
        json_mode: If True, suppress Rich markup and use plain text
                   suitable for machine parsing.
    """
    global _configured  # noqa: PLW0603

    level = logging.WARNING
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity >= 1:
        level = logging.INFO

    handler: logging.Handler
    if json_mode:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(levelname)s: %(name)s: %(message)s"))
    else:
        handler = RichHandler(
            console=error_console,
            show_time=False,
            show_path=False,
            # Log messages carry names from bills and advisories as %s
            # arguments; none uses markup on purpose. With markup on, a
            # component "[/bold]" stopped sbom merge.
            markup=False,
        )

    root = logging.getLogger("jochwacht")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a logger under the ``jochwacht`` namespace.

    Args:
        name: Typically ``__name__`` of the calling module.
    """
    if not _configured:
        setup_logging()
    return logging.getLogger(name)
