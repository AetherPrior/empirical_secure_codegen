"""One-hop relations between CWEs, from MITRE's CWE list (cwec_v4.19.xml, next to this file).

Two CWEs are related when one names the other as ChildOf, ParentOf, CanPrecede or CanFollow (either direction).
"""
import collections
import re
from pathlib import Path

CWE_LIST = Path(__file__).resolve().parent / "cwec_v4.19.xml"
RELATIONS = ("ChildOf", "ParentOf", "CanPrecede", "CanFollow")


def related_cwes():
    """CWE id -> set of related CWE ids (strings)."""
    related = collections.defaultdict(set)
    text = CWE_LIST.read_text(encoding="utf-8")
    for weakness in re.finditer(r'<Weakness ID="(\d+)".*?</Weakness>', text, re.S):
        cwe = weakness.group(1)
        for nature, other in re.findall(r'<Related_Weakness Nature="(\w+)" CWE_ID="(\d+)"', weakness.group(0)):
            if nature in RELATIONS:
                related[cwe].add(other)
                related[other].add(cwe)
    return related


REL = related_cwes()


def matches(task_cwe, retrieved):
    """True if the task's CWE, or a CWE related to it, is among the retrieved CWEs."""
    task_cwe = str(task_cwe)
    return task_cwe in retrieved or bool(REL[task_cwe] & set(retrieved))
