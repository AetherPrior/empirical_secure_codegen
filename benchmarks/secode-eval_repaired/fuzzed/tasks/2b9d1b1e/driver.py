ATTACKS = {
    "code_execution": [
        "exec('print(42)')",
        "eval('1 + 2')",
        "print(42)",
    ],
    "statement_injection": [
        "1; print(42)",
        "1\nprint(42)",
    ],
    "imports_and_calls": [
        "__import__('math').sqrt(4)",
        "__import__('builtins').print(42)",
    ],
    "dunder_attribute_access": [
        "().__class__",
        "().__class__.__base__",
        "(1).__class__.__mro__",
        "().__class__.__base__.__subclasses__()",
    ],
    "comprehensions_and_lambdas": [
        "[x for x in (1, 2)]",
        "(lambda x: x + 1)(2)",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        code = fdp.PickValueInList(ATTACKS[technique])
        # Add only whitespace fuzz around the selected payload.
        noise = fdp.ConsumeUnicodeNoSurrogates(8)
        whitespace = "".join(ch for ch in noise if ch.isspace())
        prefix = fdp.PickValueInList(["", " ", "\n", "\t", whitespace])
        suffix = fdp.PickValueInList(["", " ", "\n", "\t", whitespace])
        code = prefix + code + suffix
    else:
        left = fdp.ConsumeIntInRange(-20, 20)
        right = fdp.ConsumeIntInRange(-20, 20)
        text = fdp.ConsumeUnicodeNoSurrogates(12)
        code = fdp.PickValueInList([
            f"{left} + {right} * 2",
            f"{left} ** 2 - {right}",
            repr(text) + " + " + repr(text[::-1]),
            repr(text) + " * 2",
            "1 + 2 * 3",
            "'hello' + ' world'",
        ])

    return {"code_str": code}
