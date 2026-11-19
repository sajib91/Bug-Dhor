"""JSON-only CLI for the opt-in local Phase 6 workflow.

Usage::

    python -m bugdhor_ast.phase6.cli <action> [options]

Every invocation writes exactly one JSON object to stdout and no other text.
Successful calls use ``{\"ok\": true, \"action\": ..., \"result\": ...}``. Failures
use ``{\"ok\": false, \"action\": ..., \"error\": {\"type\": ..., \"message\": ...}}``
and a non-zero exit code. Source writes require ``--allow-source-write`` in
addition to an explicit matching patch confirmation.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ..explain.repair import AiRepairConfig
from .service import (
    Phase6Error,
    apply_preview,
    build_preview,
    explain_selected,
    list_findings,
    list_history,
    revert_applied,
    suggest_selected,
    verify_applied,
)
from .session import Phase6Session

ACTIONS = (
    "analyze",
    "explain",
    "suggest",
    "preview",
    "apply",
    "verify",
    "revert",
    "history",
)
WRITE_ACTIONS = frozenset({"apply", "revert"})
DEFAULT_SESSION = Path(".bugdhor") / "phase6-session.json"


class CliArgumentError(Exception):
    """A command-line usage error reported through the JSON envelope."""


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliArgumentError(message)


def build_parser() -> argparse.ArgumentParser:
    """Return the Phase 6 argument parser."""

    parser = _JsonArgumentParser(
        prog="python -m bugdhor_ast.phase6.cli",
        description="Local Phase 6 explanation, repair, and verification.",
    )
    parser.add_argument("action", choices=ACTIONS)
    parser.add_argument("--file", help="Source file to analyze")
    parser.add_argument(
        "--session",
        default=str(DEFAULT_SESSION),
        help=f"Local workflow session path (default: {DEFAULT_SESSION})",
    )
    parser.add_argument("--finding-id", help="Deterministic finding identifier")
    parser.add_argument("--index", type=int, help="Zero-based finding index")
    parser.add_argument("--patch-id", help="Reviewed patch identifier to apply")
    parser.add_argument("--entry-id", help="Patch history entry identifier")
    parser.add_argument(
        "--confirmation",
        help="Explicit confirmation; must equal the reviewed patch identifier",
    )
    parser.add_argument(
        "--allow-source-write",
        action="store_true",
        help="Permit an explicit apply or revert write to the source file",
    )
    parser.add_argument(
        "--ai-config",
        help="Opt-in AI provider config as JSON text or a JSON file path",
    )
    parser.add_argument(
        "--secret-value",
        action="append",
        default=[],
        help="Literal secret to redact from provider error messages (repeatable)",
    )
    return parser


def _load_ai_config(raw: str | None) -> AiRepairConfig | None:
    if not raw:
        return None
    try:
        if raw.lstrip().startswith("{"):
            payload = json.loads(raw)
        else:
            payload = json.loads(Path(raw).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise Phase6Error(f"Cannot read AI repair config: {error}") from error
    return AiRepairConfig.from_dict(payload)


def _require_file(args: argparse.Namespace) -> str:
    if not args.file:
        raise Phase6Error("--file is required for this action")
    return args.file


def _require_session(args: argparse.Namespace) -> Phase6Session:
    return Phase6Session.load(args.session)


def _require_write_permission(args: argparse.Namespace) -> None:
    if not args.allow_source_write:
        raise Phase6Error(
            "Source writes are disabled; pass --allow-source-write to permit "
            "an explicitly approved apply or revert."
        )


def _require_confirmation(args: argparse.Namespace, patch_id: str) -> None:
    if not args.confirmation:
        raise Phase6Error("--confirmation is required for this action")
    if args.confirmation != patch_id:
        raise Phase6Error(
            "Approval confirmation must equal the reviewed patch identifier."
        )


def _dispatch(args: argparse.Namespace) -> dict[str, Any]:
    action = args.action
    if action == "history":
        return list_history(_require_session(args))
    if action == "verify":
        if not args.entry_id:
            raise Phase6Error("--entry-id is required for this action")
        return verify_applied(args.entry_id, _require_session(args))

    if action == "analyze":
        return list_findings(_require_file(args))
    if action == "explain":
        return explain_selected(
            _require_file(args), finding_id=args.finding_id, index=args.index
        )
    if action == "suggest":
        return suggest_selected(
            _require_file(args),
            finding_id=args.finding_id,
            index=args.index,
            ai_config=_load_ai_config(args.ai_config),
            secret_values=tuple(args.secret_value),
        )
    if action == "preview":
        return build_preview(
            _require_file(args),
            finding_id=args.finding_id,
            index=args.index,
            session=_require_session(args),
        )
    if action == "apply":
        file = _require_file(args)
        _require_write_permission(args)
        if not args.patch_id:
            raise Phase6Error("--patch-id is required for this action")
        _require_confirmation(args, args.patch_id)
        return apply_preview(
            file,
            patch_id=args.patch_id,
            confirmation=args.confirmation,
            session=_require_session(args),
        )
    if action == "revert":
        _require_write_permission(args)
        if not args.entry_id:
            raise Phase6Error("--entry-id is required for this action")
        session = _require_session(args)
        entry = session.history.get(args.entry_id)
        if entry is None:
            raise Phase6Error(f"Unknown history entry: {args.entry_id}")
        _require_confirmation(args, entry.patch_id)
        return revert_applied(
            args.entry_id,
            confirmation=args.confirmation,
            session=session,
        )
    raise Phase6Error(f"Unsupported action: {action}")


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def run(argv: list[str] | None = None) -> int:
    """Execute one CLI action and return a process exit code."""

    parser = build_parser()
    action: str | None = None
    try:
        args = parser.parse_args(argv)
        action = args.action
        result = _dispatch(args)
    except CliArgumentError as error:
        _emit(
            {
                "ok": False,
                "action": action,
                "error": {"type": "CliArgumentError", "message": str(error)},
            }
        )
        return 2
    except Exception as error:  # noqa: BLE001 - all failures must use the envelope
        _emit(
            {
                "ok": False,
                "action": action,
                "error": {"type": type(error).__name__, "message": str(error)},
            }
        )
        return 1
    _emit({"ok": True, "action": action, "result": result})
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()


__all__ = ["ACTIONS", "CliArgumentError", "build_parser", "main", "run"]
