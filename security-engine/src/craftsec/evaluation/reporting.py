"""Publication-ready statistical report export (CSV and Excel-compatible).

Exports only from provided analysis results; no values are fabricated.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Mapping, Sequence


def _stringify(v: Any) -> Any:
    if v is None:
        return ""
    if isinstance(v, bool):
        return str(v).lower()
    if isinstance(v, (int, float, str)):
        return v
    return json.dumps(v, sort_keys=True, ensure_ascii=False)


def export_rows_csv(path: str | Path, rows: Sequence[Mapping[str, Any]]) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    rows_list = [dict(r) for r in rows]
    keys: list[str] = []
    seen: set[str] = set()
    for r in rows_list:
        for k in r.keys():
            if k not in seen:
                seen.add(k); keys.append(k)
    with p.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in rows_list:
            w.writerow({k: _stringify(r.get(k)) for k in keys})
    return p


def _try_export_xlsx(path: Path, sheets: Mapping[str, Sequence[Mapping[str, Any]]]) -> bool:
    # Try openpyxl/xlsxwriter/pandas if installed; return False if unavailable.
    try:
        import openpyxl  # type: ignore
        wb = openpyxl.Workbook()
        first = True
        for name, rows in sheets.items():
            ws = wb.active if first else wb.create_sheet(title=str(name)[:31])
            if first:
                ws.title = str(name)[:31]
                first = False
            rows_list = [dict(r) for r in rows]
            keys = []
            seen = set()
            for r in rows_list:
                for k in r.keys():
                    if k not in seen:
                        seen.add(k); keys.append(k)
            ws.append(keys)
            for r in rows_list:
                ws.append([_stringify(r.get(k)) for k in keys])
        wb.save(path)
        return True
    except Exception:
        pass
    try:
        import xlsxwriter  # type: ignore
        wb = xlsxwriter.Workbook(str(path))
        for name, rows in sheets.items():
            ws = wb.add_worksheet(str(name)[:31])
            rows_list = [dict(r) for r in rows]
            keys = []
            seen = set()
            for r in rows_list:
                for k in r.keys():
                    if k not in seen:
                        seen.add(k); keys.append(k)
            for c, k in enumerate(keys):
                ws.write(0, c, k)
            for ri, r in enumerate(rows_list, start=1):
                for c, k in enumerate(keys):
                    ws.write(ri, c, _stringify(r.get(k)))
        wb.close()
        return True
    except Exception:
        pass
    try:
        import pandas as pd  # type: ignore
        with pd.ExcelWriter(path) as writer:
            for name, rows in sheets.items():
                pd.DataFrame([dict(r) for r in rows]).to_excel(writer, sheet_name=str(name)[:31], index=False)
        return True
    except Exception:
        return False


def ablation_to_rows(ablation: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for metric, comp in (ablation.get("metrics") or {}).items():
        rows.append({
            "ablation_id": ablation.get("ablationId"),
            "description": ablation.get("description"),
            "baseline_condition": ablation.get("baselineCondition"),
            "ablated_condition": ablation.get("ablatedCondition"),
            "metric": metric,
            "n_pairs": comp.get("n_pairs"),
            "missing": comp.get("missing"),
            "mean_baseline": comp.get("mean_a"),
            "mean_ablated": comp.get("mean_b"),
            "mean_difference": comp.get("mean_difference"),
            "ci_low": (comp.get("confidence_interval") or {}).get("ci_low"),
            "ci_high": (comp.get("confidence_interval") or {}).get("ci_high"),
            "bootstrap_ci_low": (comp.get("bootstrap_confidence_interval") or {}).get("ci_low"),
            "bootstrap_ci_high": (comp.get("bootstrap_confidence_interval") or {}).get("ci_high"),
            "t_p_value": (comp.get("paired_t_test") or {}).get("p_value"),
            "wilcoxon_p_value": (comp.get("wilcoxon_signed_rank") or {}).get("p_value"),
            "permutation_p_value": (comp.get("permutation_test") or {}).get("p_value"),
            "effect_size_cohens_d": (comp.get("effect_size") or {}).get("value"),
            "practical_significance_note": comp.get("practical_significance_note"),
            "statistical_significance_note": comp.get("statistical_significance_note"),
        })
    return rows


def comparisons_to_rows(comparisons: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for c in comparisons:
        base = {
            "comparison_type": c.get("comparison_type"),
            "dimension": c.get("dimension"),
            "groups": ",".join(c.get("groups") or []),
            "metric": c.get("metric"),
            "sample_sizes": json.dumps(c.get("sample_sizes") or {}, sort_keys=True),
            "missing_data": json.dumps(c.get("missing_data") or {}, sort_keys=True),
            "notes": " | ".join(c.get("notes") or []),
        }
        tests = c.get("tests") or {}
        if "paired" in tests:
            p = tests["paired"]
            base.update({
                "mean_a": p.get("mean_a"), "mean_b": p.get("mean_b"), "mean_difference": p.get("mean_difference"),
                "permutation_p_value": (p.get("permutation_test") or {}).get("p_value"),
                "t_p_value": (p.get("paired_t_test") or {}).get("p_value"),
                "effect_size_cohens_d": (p.get("effect_size") or {}).get("value"),
            })
        if "mann_whitney_u" in tests:
            base["mann_whitney_p_value"] = (tests.get("mann_whitney_u") or {}).get("p_value")
            base["cliffs_delta"] = (tests.get("cliffs_delta") or {}).get("value")
        rows.append(base)
    return rows


def export_statistical_report(
    out_dir: str | Path,
    *,
    ablations: Sequence[Mapping[str, Any]] | None = None,
    ablation_correction: Mapping[str, Any] | None = None,
    comparisons: Sequence[Mapping[str, Any]] | None = None,
    comparison_correction: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    sheets: dict[str, list[dict[str, Any]]] = {}
    written: dict[str, str] = {}

    if ablations:
        ab_rows: list[dict[str, Any]] = []
        for a in ablations:
            ab_rows.extend(ablation_to_rows(a))
        sheets["ablations"] = ab_rows
        written["ablations_csv"] = str(export_rows_csv(out / "ablations.csv", ab_rows))
    if ablation_correction:
        corr_rows = list(ablation_correction.get("entries") or [])
        sheets["ablation_correction"] = corr_rows
        written["ablation_correction_csv"] = str(export_rows_csv(out / "ablation_multiple_comparisons.csv", corr_rows))
    if comparisons:
        cmp_rows = comparisons_to_rows(comparisons)
        sheets["comparisons"] = cmp_rows
        written["comparisons_csv"] = str(export_rows_csv(out / "comparisons.csv", cmp_rows))
    if comparison_correction:
        corr_rows = list(comparison_correction.get("entries") or [])
        sheets["comparison_correction"] = corr_rows
        written["comparison_correction_csv"] = str(export_rows_csv(out / "comparison_multiple_comparisons.csv", corr_rows))
    if metadata:
        meta_rows = [{"key": k, "value": _stringify(v)} for k, v in dict(metadata).items()]
        sheets["metadata"] = meta_rows
        written["metadata_csv"] = str(export_rows_csv(out / "metadata.csv", meta_rows))

    # Excel-compatible: try xlsx, else write a note and rely on CSVs (Excel-compatible)
    xlsx_path = out / "statistical_report.xlsx"
    xlsx_ok = _try_export_xlsx(xlsx_path, sheets) if sheets else False
    if xlsx_ok:
        written["xlsx"] = str(xlsx_path)
    else:
        note = out / "EXCEL_README.txt"
        note.write_text(
            "XLSX writer (openpyxl/xlsxwriter/pandas ExcelWriter) not available in this environment.\n"
            "Publication-ready CSV outputs are provided and are Excel-compatible.\n",
            encoding="utf-8",
        )
        written["xlsx"] = "unavailable"
        written["excel_note"] = str(note)

    return {"written": written, "xlsxGenerated": xlsx_ok}


__all__ = [
    "ablation_to_rows",
    "comparisons_to_rows",
    "export_rows_csv",
    "export_statistical_report",
]
