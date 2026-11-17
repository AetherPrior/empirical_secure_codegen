#!/usr/bin/env python3
"""Sample per-CWE annotation examples from GRPO parquet files into an XLSX file."""

from __future__ import annotations

import argparse
import json
import random
import re
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape


BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_INPUTS = {
    "c": BASE_DIR / "data/datasets_rl/c_cwe_GRPO_train.parquet",
    "cpp": BASE_DIR / "data/datasets_rl/cpp_cwe_GRPO_train.parquet",
    "python": BASE_DIR / "data/datasets_rl/python_cwe_GRPO_train.parquet",
}
DEFAULT_OUTPUT = BASE_DIR / "data_annotation.xlsx"
EXCEL_CELL_LIMIT = 32767


def normalize_cwe(value: Any) -> str:
    if value is None:
        return ""
    match = re.search(r"(\d+)", str(value))
    if match:
        return f"CWE-{match.group(1)}"
    return str(value).strip().upper()


def cwe_sort_key(cwe: str) -> tuple[int, str]:
    match = re.search(r"(\d+)", cwe)
    if match:
        return int(match.group(1)), cwe
    return 10**9, cwe


def load_json(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return value


def first_user_message(prompt: Any) -> str:
    if isinstance(prompt, list):
        for message in prompt:
            if not isinstance(message, dict):
                continue
            if message.get("role") == "user":
                content = message.get("content")
                if isinstance(content, str) and content.strip():
                    return content.strip()
    if isinstance(prompt, str):
        return prompt.strip()
    return ""


def first_text(mapping: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


class SourceSolutionLookup:
    """Recover generated solutions that were not preserved in older parquet schemas."""

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        self._cache: dict[tuple[str, str], dict[int, str]] = {}

    def get(self, lang: str, cwe: str, index: Any) -> str:
        try:
            row_index = int(index)
        except (TypeError, ValueError):
            return ""

        cwe_norm = normalize_cwe(cwe)
        if not cwe_norm:
            return ""

        key = (lang, cwe_norm)
        if key not in self._cache:
            self._cache[key] = self._load(lang, cwe_norm)
        return self._cache[key].get(row_index, "")

    def _load(self, lang: str, cwe: str) -> dict[int, str]:
        cwe_dir = cwe.lower()
        path = self.base_dir / "data" / "pipeline_runs" / lang / cwe_dir / "4_valid.jsonl"
        solutions: dict[int, str] = {}
        if not path.is_file():
            return solutions

        with path.open("r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                solution = first_text(
                    row,
                    (
                        "generated_code",
                        f"candidate_{lang}",
                        "candidate_cpp",
                        "candidate_c",
                        "solution",
                    ),
                )
                if solution:
                    solutions[idx] = solution
        return solutions


def read_parquet_rows(path: Path) -> list[dict[str, Any]]:
    try:
        import pyarrow.parquet as pq  # type: ignore
    except Exception as exc:  # pragma: no cover - dependency guard
        raise RuntimeError("pyarrow is required to read the parquet inputs.") from exc

    return pq.read_table(path).to_pylist()


def extract_annotation_row(
    row: dict[str, Any],
    *,
    lang: str,
    solution_lookup: SourceSolutionLookup,
) -> dict[str, Any]:
    prompt = row.get("prompt")
    if prompt is None:
        prompt = load_json(row.get("prompt_json"), [])

    reward_model = row.get("reward_model")
    if reward_model is None:
        reward_model = load_json(row.get("reward_model_json"), {})
    if not isinstance(reward_model, dict):
        reward_model = {}
    ground_truth = reward_model.get("ground_truth") or {}
    if not isinstance(ground_truth, dict):
        ground_truth = {}

    extra_info = row.get("extra_info")
    if extra_info is None:
        extra_info = load_json(row.get("extra_info_json"), {})
    if not isinstance(extra_info, dict):
        extra_info = {}

    cwe = normalize_cwe(
        extra_info.get("cwe")
        or extra_info.get("cwe_id")
        or ground_truth.get("cwe")
        or row.get("data_source")
    )
    source_index = extra_info.get("index", "")
    solution = first_text(
        extra_info,
        (
            "generated_code",
            f"candidate_{lang}",
            "candidate_cpp",
            "candidate_c",
            "solution",
        ),
    )
    if not solution:
        solution = first_text(ground_truth, ("generated_code", "solution", "oracle_solution"))
    if not solution:
        solution = solution_lookup.get(lang, cwe, source_index)

    return {
        "language": lang,
        "cwe": cwe,
        "source_index": source_index,
        "function_name": extra_info.get("function_name") or ground_truth.get("function_name") or "",
        "user_prompt": first_text(extra_info, ("user_prompt",)) or first_user_message(prompt),
        "test_code": ground_truth.get("test_code", ""),
        "ground_truth_solution": solution,
    }


def sample_per_cwe(
    rows: list[dict[str, Any]],
    *,
    per_cwe: int,
    rng: random.Random,
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        cwe = row.get("cwe")
        if isinstance(cwe, str) and cwe:
            grouped[cwe].append(row)

    sampled: list[dict[str, Any]] = []
    for cwe in sorted(grouped, key=cwe_sort_key):
        cwe_rows = grouped[cwe]
        if len(cwe_rows) <= per_cwe:
            chosen = list(cwe_rows)
        else:
            chosen = rng.sample(cwe_rows, per_cwe)
        chosen.sort(key=lambda item: str(item.get("source_index", "")))
        sampled.extend(chosen)
    return sampled


def clean_cell_text(value: Any) -> str:
    text = "" if value is None else str(value)
    text = "".join(
        ch
        for ch in text
        if ch in "\t\n\r" or ord(ch) >= 0x20
    )
    if len(text) > EXCEL_CELL_LIMIT:
        marker = "\n...[truncated to fit Excel cell limit]"
        text = text[: EXCEL_CELL_LIMIT - len(marker)] + marker
    return text


def col_name(index: int) -> str:
    name = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name


def cell_xml(row_idx: int, col_idx: int, value: Any, style: int) -> str:
    ref = f"{col_name(col_idx)}{row_idx}"
    text = escape(clean_cell_text(value), {'"': "&quot;"})
    return (
        f'<c r="{ref}" t="inlineStr" s="{style}">'
        f'<is><t xml:space="preserve">{text}</t></is></c>'
    )


def sheet_xml(rows: list[dict[str, Any]], columns: list[str]) -> str:
    xml_rows = []
    header = "".join(cell_xml(1, idx, column, 1) for idx, column in enumerate(columns, 1))
    xml_rows.append(f'<row r="1">{header}</row>')
    for row_idx, row in enumerate(rows, 2):
        cells = "".join(
            cell_xml(row_idx, col_idx, row.get(column, ""), 2)
            for col_idx, column in enumerate(columns, 1)
        )
        xml_rows.append(f'<row r="{row_idx}">{cells}</row>')

    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetViews><sheetView workbookViewId="0"/></sheetViews>
  <sheetFormatPr defaultRowHeight="15"/>
  <cols>
    <col min="1" max="1" width="12" customWidth="1"/>
    <col min="2" max="2" width="14" customWidth="1"/>
    <col min="3" max="3" width="12" customWidth="1"/>
    <col min="4" max="4" width="24" customWidth="1"/>
    <col min="5" max="7" width="80" customWidth="1"/>
  </cols>
  <sheetData>
    {''.join(xml_rows)}
  </sheetData>
</worksheet>
'''


def write_xlsx(path: Path, sheets: dict[str, list[dict[str, Any]]], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sheet_names = list(sheets)

    workbook_sheets = "\n".join(
        f'<sheet name="{escape(name)}" sheetId="{idx}" r:id="rId{idx}"/>'
        for idx, name in enumerate(sheet_names, 1)
    )
    workbook_rels = "\n".join(
        f'<Relationship Id="rId{idx}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{idx}.xml"/>'
        for idx, _ in enumerate(sheet_names, 1)
    )
    style_rel_id = len(sheet_names) + 1

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
'''
            + "".join(
                f'  <Override PartName="/xl/worksheets/sheet{idx}.xml" '
                'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>\n'
                for idx, _ in enumerate(sheet_names, 1)
            )
            + "</Types>\n",
        )
        zf.writestr(
            "_rels/.rels",
            '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>
''',
        )
        zf.writestr(
            "xl/workbook.xml",
            f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    {workbook_sheets}
  </sheets>
</workbook>
''',
        )
        zf.writestr(
            "xl/_rels/workbook.xml.rels",
            f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
{workbook_rels}
  <Relationship Id="rId{style_rel_id}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>
''',
        )
        zf.writestr(
            "xl/styles.xml",
            '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="2"><font/><font><b/></font></fonts>
  <fills count="1"><fill><patternFill patternType="none"/></fill></fills>
  <borders count="1"><border/></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="3">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf>
  </cellXfs>
</styleSheet>
''',
        )
        for idx, (sheet_name, rows) in enumerate(sheets.items(), 1):
            zf.writestr(f"xl/worksheets/sheet{idx}.xml", sheet_xml(rows, columns))


def _fence_lang(lang: str) -> str:
    return {"c": "c", "cpp": "cpp", "python": "python", "javascript": "javascript"}.get(lang, lang)


def _has_setup_block(text: str) -> bool:
    return "Provided setup" in text or "**setup_code (runs before" in text


def _prompt_base(text: str) -> str:
    if not text:
        return ""
    for marker in ("## Provided setup", "**setup_code (runs before"):
        if marker in text:
            return text.split(marker, 1)[0].rstrip()
    return text.rstrip()


def _setup_code_suffix(setup_code: str, *, lang: str) -> str:
    setup = (setup_code or "").strip()
    if not setup:
        return ""
    fence = _fence_lang(lang)
    return (
        f"\n\n## Provided setup (use as-is; do not redefine)\n"
        f"```{fence}\n{setup.rstrip()}\n```\n"
    )


class SetupCodeLookup:
    """Resolve ``setup_code`` for existing annotation rows without replacing task text."""

    def __init__(self, base_dir: Path) -> None:
        self._by_index: dict[tuple[str, str, str], str] = {}
        self._by_function: dict[tuple[str, str, str], str] = {}
        self._by_prompt: dict[tuple[str, str], str] = {}
        self._load_sources(base_dir)

    def get(self, *, lang: str, cwe: str, source_index: Any, function_name: str, user_prompt: str) -> str:
        cwe_norm = normalize_cwe(cwe)
        idx = str(source_index)
        fn = (function_name or "").strip()
        base = _prompt_base(user_prompt)
        return (
            self._by_index.get((lang, cwe_norm, idx), "")
            or self._by_function.get((lang, cwe_norm, fn), "")
            or self._by_prompt.get((lang, base), "")
        )

    def _ingest_row(self, row: dict[str, Any], *, lang: str | None = None) -> None:
        extra_info = row.get("extra_info")
        if extra_info is None:
            extra_info = load_json(row.get("extra_info_json"), {})
        if not isinstance(extra_info, dict):
            extra_info = {}

        reward_model = row.get("reward_model")
        if reward_model is None:
            reward_model = load_json(row.get("reward_model_json"), {})
        if not isinstance(reward_model, dict):
            reward_model = {}
        ground_truth = reward_model.get("ground_truth") or {}
        if not isinstance(ground_truth, dict):
            ground_truth = {}

        setup_code = ground_truth.get("setup_code")
        if not isinstance(setup_code, str) or not setup_code.strip():
            return

        row_lang = lang or extra_info.get("lang") or extra_info.get("language") or ground_truth.get("language")
        if not isinstance(row_lang, str) or not row_lang.strip():
            return
        row_lang = row_lang.strip()

        cwe = normalize_cwe(
            extra_info.get("cwe")
            or extra_info.get("cwe_id")
            or ground_truth.get("cwe")
            or row.get("data_source")
        )
        if not cwe:
            return

        index = extra_info.get("index")
        if index is not None and str(index) != "":
            self._by_index[(row_lang, cwe, str(index))] = setup_code

        function_name = extra_info.get("function_name") or ground_truth.get("function_name")
        if isinstance(function_name, str) and function_name.strip():
            self._by_function[(row_lang, cwe, function_name.strip())] = setup_code

        prompt_text = extra_info.get("user_prompt")
        if not isinstance(prompt_text, str) or not prompt_text.strip():
            prompt_text = first_user_message(row.get("prompt"))
        base = _prompt_base(prompt_text)
        if base:
            self._by_prompt[(row_lang, base)] = setup_code

    def _load_sources(self, base_dir: Path) -> None:
        datasets_dir = base_dir / "data" / "datasets_rl"
        for lang in ("c", "cpp", "python"):
            for name in (f"{lang}_cwe_GRPO.parquet", f"{lang}_cwe_GRPO_train.parquet"):
                path = datasets_dir / name
                if path.is_file():
                    for row in read_parquet_rows(path):
                        self._ingest_row(row, lang=lang)

        jsonl_paths = sorted(datasets_dir.glob("*.jsonl"))
        verl_dir = base_dir.parent / "verl" / "datasets" / "seccode"
        jsonl_paths.extend(sorted(verl_dir.glob("*GRPO*.jsonl")) if verl_dir.is_dir() else [])
        for path in jsonl_paths:
            if not path.is_file():
                continue
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self._ingest_row(row)


def update_prompts_in_workbook(
    path: Path,
    *,
    setup_lookup: SetupCodeLookup | None = None,
) -> tuple[int, int, int, list[str]]:
    """Append setup blocks to ``user_prompt`` cells; leave all other columns untouched."""
    try:
        import openpyxl
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("openpyxl is required for in-place prompt updates.") from exc

    lookup = setup_lookup or SetupCodeLookup(BASE_DIR)
    workbook = openpyxl.load_workbook(path)
    updated = skipped = missing = 0
    warnings: list[str] = []

    for sheet_name in workbook.sheetnames:
        worksheet = workbook[sheet_name]
        headers = {
            worksheet.cell(1, column).value: column
            for column in range(1, worksheet.max_column + 1)
            if worksheet.cell(1, column).value
        }
        prompt_col = headers.get("user_prompt")
        if prompt_col is None:
            warnings.append(f"{sheet_name}: no user_prompt column")
            continue
        for required in ("language", "cwe", "source_index", "function_name"):
            if required not in headers:
                warnings.append(f"{sheet_name}: missing {required} column")
                break
        else:
            for row_idx in range(2, worksheet.max_row + 1):
                current = worksheet.cell(row_idx, prompt_col).value
                prompt_text = current if isinstance(current, str) else ("" if current is None else str(current))
                if _has_setup_block(prompt_text):
                    skipped += 1
                    continue

                lang = worksheet.cell(row_idx, headers["language"]).value
                cwe = worksheet.cell(row_idx, headers["cwe"]).value
                source_index = worksheet.cell(row_idx, headers["source_index"]).value
                function_name = worksheet.cell(row_idx, headers["function_name"]).value
                if not isinstance(lang, str):
                    missing += 1
                    continue

                setup_code = lookup.get(
                    lang=lang,
                    cwe=str(cwe),
                    source_index=source_index,
                    function_name=str(function_name or ""),
                    user_prompt=prompt_text,
                )
                suffix = _setup_code_suffix(setup_code, lang=lang)
                if not suffix:
                    missing += 1
                    warnings.append(
                        f"{sheet_name} row {row_idx}: no setup_code for "
                        f"{cwe} index={source_index} fn={function_name}"
                    )
                    continue

                worksheet.cell(row_idx, prompt_col).value = _prompt_base(prompt_text) + suffix
                updated += 1

    workbook.save(path)
    return updated, skipped, missing, warnings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sample annotation rows from C, C++, and Python GRPO train parquet files."
    )
    parser.add_argument("--per-cwe", type=int, default=10, help="Rows to sample per CWE.")
    parser.add_argument("--seed", type=int, default=0, help="Random seed for sampling.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output .xlsx path.")
    parser.add_argument(
        "--update-prompts-in-place",
        action="store_true",
        help=(
            "Update only user_prompt cells in an existing workbook by appending setup_code blocks. "
            "Does not resample rows or change annotation columns."
        ),
    )
    parser.add_argument(
        "--workbook",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Workbook path for --update-prompts-in-place (default: data_annotation.xlsx).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.update_prompts_in_place:
        path = args.workbook
        if not path.is_file():
            raise FileNotFoundError(f"Workbook not found: {path}")
        backup = path.with_name(f"{path.stem}.bak{path.suffix}")
        backup.write_bytes(path.read_bytes())
        updated, skipped, missing, warnings = update_prompts_in_workbook(path)
        print(f"Backup: {backup}")
        print(f"Updated user_prompt cells: {updated}")
        print(f"Already had setup block: {skipped}")
        print(f"No setup_code found (left unchanged): {missing}")
        if warnings:
            print("Warnings (first 20):")
            for line in warnings[:20]:
                print(f"  {line}")
            if len(warnings) > 20:
                print(f"  ... and {len(warnings) - 20} more")
        print(f"Wrote {path}")
        return

    rng = random.Random(args.seed)
    solution_lookup = SourceSolutionLookup(BASE_DIR)
    columns = [
        "language",
        "cwe",
        "source_index",
        "function_name",
        "user_prompt",
        "test_code",
        "ground_truth_solution",
    ]

    sheets: dict[str, list[dict[str, Any]]] = {}
    for lang, path in DEFAULT_INPUTS.items():
        if not path.is_file():
            raise FileNotFoundError(f"Missing input parquet for {lang}: {path}")
        rows = [
            extract_annotation_row(row, lang=lang, solution_lookup=solution_lookup)
            for row in read_parquet_rows(path)
        ]
        sampled = sample_per_cwe(rows, per_cwe=args.per_cwe, rng=rng)
        sheets[lang] = sampled
        missing_solutions = sum(1 for row in sampled if not row["ground_truth_solution"])
        print(
            f"{lang}: sampled {len(sampled)} rows from "
            f"{len({row['cwe'] for row in sampled})} CWEs"
            + (f" ({missing_solutions} missing solutions)" if missing_solutions else "")
        )

    write_xlsx(args.output, sheets, columns)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
