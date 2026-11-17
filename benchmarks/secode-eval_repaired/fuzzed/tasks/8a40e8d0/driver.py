ATTACKS = {
    "direct_builtin_calls": [
        "exec('print(123)')",
        "eval('2 + 3')",
        "sum([1, 2, 3])",
    ],
    "dynamic_import": [
        "__import__('math').sqrt(16)",
        "__import__('builtins').eval('2 + 3')",
    ],
    "dunder_attribute_access": [
        "().__class__.__mro__",
        "().__class__.__bases__",
        "(1).__class__.__mro__",
    ],
    "comprehension_and_lambda": [
        "[x for x in (1, 2, 3)]",
        "[(lambda: __import__('math').sqrt(9))()]",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        expr = fdp.PickValueInList(ATTACKS[family])

        # Add harmless whitespace and optionally wrap the payload in parentheses.
        ws = "".join(
            c for c in fdp.ConsumeUnicodeNoSurrogates(4) if c in " \t\n"
        )
        expr = ws + expr + ws
        if fdp.ConsumeBool():
            expr = "(" + expr + ")"
    else:
        a = fdp.ConsumeIntInRange(-20, 20)
        b = fdp.ConsumeIntInRange(1, 20)
        op = fdp.PickValueInList(["+", "-", "*", "/", "//", "%"])
        expr = f"{a} {op} {b}"

    return {"expr_string": expr}
