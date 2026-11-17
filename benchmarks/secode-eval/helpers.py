from typing import Any, List, Optional
import re

def extract_text_from_message_item(item: Any) -> str:
    """
    Responses API returns output as a list of items. For a 'message' item,
    the text usually lives in item.content[*].text.
    This helper is defensive against slight SDK/schema variations.
    """
    parts = []
    content = getattr(item, "content", None)
    if isinstance(content, list):
        for part in content:
            # object-style attr or dict-style access:
            text = getattr(part, "text", None)
            if text is None and isinstance(part, dict):
                text = part.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "\n".join(parts).strip()

def extract_reasoning_summary(item: Any) -> Optional[str]:
    """
    Reasoning summaries typically appear on an item with type == 'reasoning'.
    Some SDK versions expose a 'summary' field (string or list). Be robust.
    """
    # Try attribute-first
    summary = getattr(item, "summary", None)
    if isinstance(summary, list):
        # Some responses return a list of segments; join them.
        summary = " ".join(s for s in summary if isinstance(s, str))
    if isinstance(summary, str) and summary.strip():
        return summary.strip()

    # Fallbacks: sometimes the summary text may be nested in 'content'
    content = getattr(item, "content", None)
    if isinstance(content, list):
        texts: List[str] = []
        for c in content:
            text = getattr(c, "text", None) if hasattr(c, "text") else (c.get("text") if isinstance(c, dict) else None)
            if isinstance(text, str):
                texts.append(text)
        if texts:
            return "\n".join(texts).strip()

    # As a last resort, if the item is a dict, peek keys
    if isinstance(item, dict):
        if isinstance(item.get("summary"), list):
            return " ".join(item["summary"])
        if isinstance(item.get("summary"), str):
            return item["summary"].strip()
    return None

def extract_generated_code(generation: Optional[str]) -> str:
    """
    Parses the generation output to extract the code from markdown code blocks.
    Handles multiple languages (python, java, cpp, c, etc.).
    If no code block is found, returns the stripped generation as-is.
    """
    if generation is None:
        return "", ""
    if not isinstance(generation, str):
        generation = str(generation)

    # extract the response after </think>, if present
    rest_of_generation = ""
    think_response = re.search(r"</think>(.*?)$", generation, re.DOTALL)
    if think_response:
        generation = think_response.group(1)
        rest_of_generation = think_response.group(0)

    # Match code blocks with any language tag or no tag: ```python, ```java, ```cpp, ```
    code_blocks = re.findall(r"```(?:\w+)?\s*\n(.*?)\n```", generation, re.DOTALL)
    if code_blocks:
        return "\n".join(code_blocks).strip(), rest_of_generation
    else:
        return generation.strip(), rest_of_generation