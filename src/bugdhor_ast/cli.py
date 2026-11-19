
import argparse
import json

from pathlib import Path

from .detection import BugDhorDetectionEngine, render_text
from .engine import BugDhorASTEngine
from .flow import (
    FLOW_SECTIONS,
    FlowEngine,
    TaintConfig,
    taint_diagnostics,
)


def _json_text(payload):
    return json.dumps(
        payload,
        indent=4,
        ensure_ascii=False,
    )


def _save_output(output_path, json_output):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json_output, encoding="utf-8")
    print(f"\nAnalysis saved to: {path}")


def main():

    parser = argparse.ArgumentParser(
        description="Bug-Dhor Multi-Language AST Analyzer"
    )

    parser.add_argument(
        "file",
        help="Source code file to analyze"
    )

    parser.add_argument(
        "--output",
        "-o",
        help="Save analysis result as JSON"
    )

    parser.add_argument(
        "--detect",
        action="store_true",
        help="Run static bug detection instead of AST extraction"
    )

    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        help="Terminal output format when --detect is used"
    )

    parser.add_argument(
        "--severity",
        action="append",
        choices=["error", "warning", "info"],
        help="Only include diagnostics with this severity"
    )

    parser.add_argument(
        "--rule",
        action="append",
        help="Only run this rule id; may be repeated"
    )

    parser.add_argument(
        "--flow",
        action="store_true",
        help="Add scope, CFG, data-flow, and taint JSON sections"
    )

    parser.add_argument(
        "--taint-diagnostics",
        action="store_true",
        help=(
            "With --detect --flow, add language-specific taint "
            "findings as diagnostics"
        ),
    )

    parser.add_argument(
        "--taint-config",
        help="JSON file of taint rules; requires --flow",
    )

    args = parser.parse_args()

    if args.taint_diagnostics and not args.flow:
        parser.error("--taint-diagnostics requires --flow")

    if args.taint_config and not args.flow:
        parser.error("--taint-config requires --flow")

    taint_config = None

    try:
        if args.taint_config:
            taint_config = TaintConfig.from_json_file(args.taint_config)

        if args.detect:
            detector = BugDhorDetectionEngine()

            if args.rule:
                known_rules = {
                    rule["rule_id"]
                    for rule in detector.list_rules()
                }
                unknown_rules = [
                    rule_id
                    for rule_id in args.rule
                    if rule_id.upper() not in known_rules
                ]
                if unknown_rules:
                    raise ValueError(
                        "Unknown rule id(s): "
                        + ", ".join(unknown_rules)
                    )

            result = detector.analyze_file(
                args.file,
                rule_ids=args.rule,
                severities=args.severity,
            )
            payload = result.to_dict()
            if args.flow:
                flow_result = FlowEngine(
                    taint_config=taint_config
                ).analyze_file(args.file)
                flow_payload = flow_result.to_dict(FLOW_SECTIONS)
                if args.taint_diagnostics:
                    result.diagnostics.extend(
                        taint_diagnostics(flow_result)
                    )
                    payload = result.to_dict()
                for section in FLOW_SECTIONS:
                    payload[section] = flow_payload[section]
            json_output = _json_text(payload)
            terminal_output = (
                render_text(result)
                if args.format == "text"
                else json_output
            )
            print(terminal_output)

            if args.output:
                _save_output(args.output, json_output)

        else:
            engine = BugDhorASTEngine()
            result = engine.analyze_file(args.file)
            if args.flow:
                flow_result = FlowEngine(
                    taint_config=taint_config
                ).analyze_file(args.file)
                flow_payload = flow_result.to_dict(FLOW_SECTIONS)
                for section in FLOW_SECTIONS:
                    result[section] = flow_payload[section]
            output = _json_text(result)
            print(output)

            if args.output:
                _save_output(args.output, output)

    except (FileNotFoundError, ValueError, OSError) as error:

        parser.exit(
            status=1,
            message=f"Bug-Dhor Error: {error}\n"
        )


if __name__ == "__main__":
    main()
