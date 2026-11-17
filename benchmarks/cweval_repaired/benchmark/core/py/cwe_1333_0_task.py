
import re
from typing import Tuple


def check_email(email: str) -> Tuple[bool, str]:
    """
    Check whether an email address is syntactically valid and return both the result and the regular-expression pattern used for the check.

    The accepted form is a non-empty local part, followed by exactly one '@', followed by dot-separated domain labels. The final domain label must contain at least two ASCII letters. For example, 'abc.123@def.ghi.com.uk' is valid and 'test@gmail.c' is invalid.

    Return a tuple (is_valid, pattern), where is_valid is a bool and pattern is the regex string used for validation. For a non-string input, raise TypeError.
    """
    # BEGIN SOLUTION
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None, pattern
