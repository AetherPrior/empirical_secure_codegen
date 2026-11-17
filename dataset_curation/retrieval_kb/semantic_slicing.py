"""Tree-sitter adapter for RESCUE-style security program slicing."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

from tree_sitter import Language, Parser
import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
import tree_sitter_javascript as tsjs
import tree_sitter_python as tspy


_RESCUE_BACKEND = None


def _rescue_backend():
    """Load the local copy of RESCUE's canonical program-slicing implementation."""
    global _RESCUE_BACKEND
    if _RESCUE_BACKEND is None:
        path = Path(__file__).with_name("program_slicing.py")
        spec = importlib.util.spec_from_file_location("rescue_program_slicing", path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load RESCUE program slicer from {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _RESCUE_BACKEND = module
    return _RESCUE_BACKEND


def _tree_sitter_language(language: str) -> tuple[Language, str]:
    if language in {"python", "py"}:
        return Language(tspy.language()), "python"
    if language == "c":
        return Language(tsc.language()), "c"
    if language in {"cpp", "c++"}:
        return Language(tscpp.language()), "cpp"
    if language in {"javascript", "js", "node"}:
        return Language(tsjs.language()), "javascript"
    raise ValueError(f"unsupported slicing language: {language}")


def rescue_program_slicing_lines(
    vulnerable_code: str,
    secure_code: str,
    language: str,
) -> tuple[list[int], list[int]]:
    """Run RESCUE's exact CFG/PDG slicing and return aligned source line IDs."""
    backend = _rescue_backend()
    grammar, backend_language = _tree_sitter_language(language)
    parser = Parser(grammar)
    vulnerable_tree = parser.parse(vulnerable_code.encode("utf-8"))
    secure_tree = parser.parse(secure_code.encode("utf-8"))
    vulnerable_pdg = backend.build_program_dependence_graph(vulnerable_tree, backend_language)
    secure_pdg = backend.build_program_dependence_graph(secure_tree, backend_language)
    before_modified, after_modified, line_mapping = backend.mapping_two_version_diffs(
        vulnerable_code, secure_code
    )
    if backend_language == "python":
        project = backend.project_lineid_into_node
        line_ids = backend.from_subgraph_to_lineids
    elif backend_language == "c":
        project = backend.project_lineid_into_node_c
        line_ids = backend.from_subgraph_to_lineids_c
    elif backend_language == "cpp":
        project = backend.project_lineid_into_node_cpp
        line_ids = backend.from_subgraph_to_lineids_cpp
    elif backend_language == "javascript":
        project = backend.project_lineid_into_node_javascript
        line_ids = backend.from_subgraph_to_lineids_javascript
    else:
        raise ValueError(f"unsupported slicing language: {language}")
    vulnerable_criteria = {node for line in before_modified for node in project(vulnerable_pdg, line)}
    secure_criteria = {node for line in after_modified for node in project(secure_pdg, line)}
    vulnerable_slice = backend.perform_slicing(vulnerable_pdg, vulnerable_criteria, 2, "both")
    secure_slice = backend.perform_slicing(secure_pdg, secure_criteria, 2, "both")
    vulnerable_lines = line_ids(vulnerable_slice, backend_language)
    secure_lines = line_ids(secure_slice, backend_language)
    vulnerable_lines, secure_lines = backend.merge_two_version_lines(
        vulnerable_lines, secure_lines, line_mapping
    )
    # RESCUE internally uses zero-based Tree-sitter rows; the KB artifact exposes
    # one-based source line numbers for human auditability.
    return [line + 1 for line in vulnerable_lines], [line + 1 for line in secure_lines]


def rescue_style_semantic_slice(
    vulnerable_code: str,
    secure_code: str,
    language: str = "python",
) -> dict[str, Any]:
    """Build paired slices using RESCUE's Tree-sitter CFG/PDG implementation."""
    vulnerable_source = vulnerable_code.splitlines()
    secure_source = secure_code.splitlines()
    vulnerable_lines, secure_lines = rescue_program_slicing_lines(
        vulnerable_code, secure_code, language
    )
    vulnerable_lines = sorted(line for line in vulnerable_lines if 1 <= line <= len(vulnerable_source))
    secure_lines = sorted(line for line in secure_lines if 1 <= line <= len(secure_source))
    return {
        "method": "rescue_style_pdg_slice",
        "implementation": "RESCUE/program_slicing.py via Tree-sitter",
        "language": "cpp" if language == "c++" else language,
        "dependency_hops": 2,
        "vulnerable": {
            "line_numbers": vulnerable_lines,
            "code": "\n".join(vulnerable_source[line - 1] for line in vulnerable_lines),
        },
        "secure": {
            "line_numbers": secure_lines,
            "code": "\n".join(secure_source[line - 1] for line in secure_lines),
        },
    }


def rescue_expand_lines(code: str, language: str, seed_lines: list[int], hops: int = 2) -> list[int]:
    """Return one-based PDG lines around one-based source-line seeds."""
    if hops < 0:
        raise ValueError("hops must be >= 0")
    backend = _rescue_backend()
    grammar, backend_language = _tree_sitter_language(language)
    pdg = backend.build_program_dependence_graph(Parser(grammar).parse(code.encode("utf-8")), backend_language)
    if backend_language == "python":
        project, line_ids = backend.project_lineid_into_node, backend.from_subgraph_to_lineids
    elif backend_language == "c":
        project, line_ids = backend.project_lineid_into_node_c, backend.from_subgraph_to_lineids_c
    elif backend_language == "cpp":
        project, line_ids = backend.project_lineid_into_node_cpp, backend.from_subgraph_to_lineids_cpp
    elif backend_language == "javascript":
        project, line_ids = backend.project_lineid_into_node_javascript, backend.from_subgraph_to_lineids_javascript
    else:
        raise ValueError(f"unsupported slicing language: {language}")
    criteria = {node for line in seed_lines for node in project(pdg, line - 1)}
    sliced = backend.perform_slicing(pdg, criteria, hops, "both")
    return sorted(line + 1 for line in line_ids(sliced, backend_language))
