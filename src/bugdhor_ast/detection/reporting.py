from .models import DetectionResult


def render_text(result: DetectionResult) -> str:
    """Render diagnostics in a compact terminal-friendly format."""

    lines = [
        f"Bug-Dhor diagnostics for {result.file} "
        f"({result.language})"
    ]

    if not result.diagnostics:
        lines.append("No diagnostics found.")
        return "\n".join(lines)

    for diagnostic in result.diagnostics:
        severity = diagnostic.severity.upper()
        lines.append(
            f"[{severity}] {diagnostic.rule_id} "
            f"{diagnostic.file}:{diagnostic.line}:"
            f"{diagnostic.column} - {diagnostic.message}"
        )
        lines.append(
            f"    Rule: {diagnostic.rule_name}"
        )
        lines.append(
            f"    Explanation: {diagnostic.explanation}"
        )
        if diagnostic.suggestion:
            lines.append(
                f"    Suggestion: {diagnostic.suggestion}"
            )

    summary = result.summary
    lines.append(
        "Summary: "
        f"{summary['error']} error(s), "
        f"{summary['warning']} warning(s), "
        f"{summary['info']} info, "
        f"{summary['total']} total"
    )
    return "\n".join(lines)
