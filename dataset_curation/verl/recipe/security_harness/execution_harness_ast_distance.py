"""Canonicalized AST normalized tree-edit distance (tree-sitter + zss).

Languages: python, c, cpp, javascript, go.

Compares model candidate code to ``extra_info.generated_code`` (oracle) as-is.
In python_cwe_GRPO the oracle does not embed ``setup_code``.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from tree_sitter import Node, Parser
from zss import Node as ZNode
from zss import simple_distance

try:
    from recipe.security_harness.execution_harness import simple_gen_language
    from recipe.security_harness.reward_config import debug
except ImportError:
    from execution_harness import simple_gen_language
    from reward_config import debug


_LANGS = frozenset({"python", "c", "cpp", "javascript", "go"})
_LANG_ALIASES = {
    "py": "python",
    "python3": "python",
    "python": "python",
    "c": "c",
    "c11": "c",
    "cpp": "cpp",
    "c++": "cpp",
    "cxx": "cpp",
    "cc": "cpp",
    "js": "javascript",
    "javascript": "javascript",
    "node": "javascript",
    "nodejs": "javascript",
    "go": "go",
    "golang": "go",
}
_COMMENT = frozenset({"comment", "line_comment", "block_comment"})
_GROUP = frozenset({"parenthesized_expression", "parenthesized_type"})
_STRING = frozenset(
    {
        "string",
        "concatenated_string",
        "string_literal",
        "raw_string_literal",
        "interpreted_string_literal",
        "character_literal",
        "rune_literal",
        "system_lib_string",
        "template_string",
    }
)
_STRING_DELIM = frozenset({"string_start", "string_end"})
_STRING_CONTENT = frozenset(
    {
        "string_content",
        "string_fragment",
        "escape_sequence",
        "interpreted_string_literal_content",
        "raw_string_literal_content",
    }
)
_SORT_KIDS = frozenset({"import_spec_list", "named_imports"})
# Identifier leaves are anonymized so rename-equivalent code matches.
_NAME_LEAF = frozenset(
    {
        "identifier",
        "name",
        "field_identifier",
        "type_identifier",
        "property_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
        "statement_identifier",
        "package_identifier",
        "namespace_identifier",
        "labeled_name",
    }
)
_WS = re.compile(rb"\s+")


def _norm_lang(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return _LANG_ALIASES.get(value.strip().lower().replace("_", "-"))


def _language(ground_truth: Any, extra_info: Any, override: str | None) -> str:
    if override and (resolved := _norm_lang(override)):
        return resolved
    return _norm_lang(simple_gen_language(ground_truth, extra_info)) or "python"


@lru_cache(maxsize=8)
def _parser(lang: str) -> Parser:
    from tree_sitter_language_pack import get_parser

    return get_parser(lang)


def _parse(source: str, lang: str) -> tuple[Node, bytes] | None:
    if lang not in _LANGS:
        return None

    raw = (source or "").encode("utf-8", errors="replace")
    try:
        root = _parser(lang).parse(raw).root_node
    except Exception as exc:
        debug(f"tree-sitter parse failed ({lang}): {type(exc).__name__}: {exc}")
        return None

    if root.has_error:
        debug(f"tree-sitter syntax error ({lang})")
        return None

    return root, raw


def _kids(node: Node) -> list[Node]:
    return [c for c in node.named_children if c.type not in _COMMENT]


def _text(node: Node, src: bytes) -> str:
    return _WS.sub(b" ", src[node.start_byte : node.end_byte].strip()).decode("utf-8", errors="replace")


def _plain_string(node: Node, src: bytes) -> str:
    """Quote-style-invariant content for a string with no structural kids."""
    raw = src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    if len(raw) >= 6 and raw[:3] in {'"""', "'''"} and raw[-3:] == raw[:3]:
        return raw[3:-3]
    if len(raw) >= 2 and raw[0] in {'"', "'", "`"} and raw[-1] == raw[0]:
        return raw[1:-1]
    return raw


def _tree_key(node: ZNode) -> tuple:
    return (node.label, tuple(_tree_key(c) for c in node.children))


def _to_zss(node: Node, src: bytes) -> ZNode | None:
    """Canonical labeled tree as a zss.Node."""
    if not node.is_named or node.type in _COMMENT or node.type in _STRING_DELIM:
        return None
    if node.type in _GROUP:
        kids = _kids(node)
        if len(kids) == 1:
            return _to_zss(kids[0], src)
    if node.type in _STRING_CONTENT:
        return ZNode(f"string:{src[node.start_byte : node.end_byte].decode('utf-8', errors='replace')}")
    if node.type == "system_lib_string":
        return ZNode(f"string:{_text(node, src)}")

    # Strings / templates: keep content + full interpolation subtrees (not collapsed labels).
    if node.type in _STRING:
        kids = [k for c in _kids(node) if (k := _to_zss(c, src)) is not None]
        if not kids:
            return ZNode(f"string:{_plain_string(node, src)}")
        if len(kids) == 1 and not kids[0].children and kids[0].label.startswith("string:"):
            return kids[0]
        return ZNode("string", kids)

    kids = [k for c in _kids(node) if (k := _to_zss(c, src)) is not None]
    if node.type in _SORT_KIDS:
        kids.sort(key=_tree_key)
    if not kids:
        return ZNode(f"{node.type}:{_text(node, src)}")
    return ZNode(node.type, kids)


def _size(node: ZNode) -> int:
    return 1 + sum(_size(c) for c in node.children)


def _canonical(source: str, lang: str) -> ZNode | None:
    parsed = _parse(source, lang)
    if parsed is None:
        return None
    return _to_zss(*parsed)


@lru_cache(maxsize=512)
def _cached_canonical(source: str, lang: str) -> ZNode | None:
    """Cache oracle trees; reused across rollouts in a GRPO group."""
    return _canonical(source, lang)


def _oracle(ground_truth: Any, extra_info: Any) -> str | None:
    for src in (extra_info, ground_truth):
        if isinstance(src, dict):
            val = src.get("generated_code")
            if isinstance(val, str) and val.strip():
                return val.strip()
    return None


def ast_distance(
    candidate_code: str,
    ground_truth: Any,
    extra_info: dict[str, Any] | None = None,
    *,
    language: str | None = None,
) -> dict[str, Any]:
    """Normalized TED between candidate and oracle canonical ASTs."""
    lang = _language(ground_truth, extra_info, language)
    fail = {
        "ok": False,
        "distance": None,
        "normalized_distance": None,
        "similarity": 0.0,
        "language": lang,
    }
    if lang not in _LANGS:
        return {**fail, "reason": f"unsupported_language:{lang}"}

    oracle = _oracle(ground_truth, extra_info)
    if oracle is None:
        debug("ast_distance: missing generated_code")
        return {**fail, "reason": "missing_oracle"}

    left = _canonical(candidate_code or "", lang)
    right = _cached_canonical(oracle, lang)
    if left is None or right is None:
        return {**fail, "reason": "parse_unavailable"}

    dist = float(
        simple_distance(
            left,
            right,
            label_dist=lambda a, b: 0 if a == b else 1,
        )
    )

    left_size = _size(left)
    right_size = _size(right)
    denom = max(left_size, right_size, 1)

    ndist = min(1.0, dist / denom)
    sim = 1.0 - ndist
    debug(
        f"ast_distance: lang={lang}, distance={dist}, nTED={ndist:.4f}, similarity={sim:.4f}, "
        f"cand_nodes={left_size}, oracle_nodes={right_size}"
    )
    return {
        "ok": True,
        "distance": dist,
        "normalized_distance": float(ndist),
        "similarity": float(sim),
        "language": lang,
        "candidate_nodes": left_size,
        "oracle_nodes": right_size,
        "reason": None,
    }


def ast_similarity_score(
    candidate_code: str,
    ground_truth: Any,
    extra_info: dict[str, Any] | None = None,
    **kwargs: Any,
) -> float:
    return float(ast_distance(candidate_code, ground_truth, extra_info, **kwargs).get("similarity") or 0.0)


ast_focus_distance = ast_distance
ast_focus_similarity_score = ast_similarity_score
