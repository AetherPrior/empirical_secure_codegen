ATTACKS = {
    "exec_call": [
        "exec('print(42)')",
        "exec('1 + 2')",
    ],
    "builtin_calls": [
        "print(42)",
        "__import__('builtins').print(42)",
        "__import__('builtins').eval('1 + 2')",
    ],
    "attribute_access": [
        "().__class__",
        "''.__class__.__mro__",
    ],
    "fstring_evaluation": [
        "f\"{__import__('builtins').print(42)}\"",
    ],
    "statement_injection": [
        "1; print(42)",
        "1; exec('print(42)')",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        # Comments add fuzz text without changing the payload's syntax.
        prefix = fdp.ConsumeUnicodeNoSurrogates(4).replace("\n", " ").replace("\r", " ")
        suffix = fdp.ConsumeUnicodeNoSurrogates(4).replace("\n", " ").replace("\r", " ")
        code = "# " + prefix + "\n" + payload + " # " + suffix
    else:
        left = fdp.ConsumeIntInRange(-20, 20)
        right = fdp.ConsumeIntInRange(-20, 20)
        choice = fdp.ConsumeIntInRange(0, 3)
        if choice == 0:
            code = f"{left} + {right} * 2"
        elif choice == 1:
            code = f"{left} - {right}"
        elif choice == 2:
            text = fdp.ConsumeUnicodeNoSurrogates(6)
            code = repr(text) + " + " + repr("x")
        else:
            text = fdp.ConsumeUnicodeNoSurrogates(6)
            code = repr(text) + " * 2"

    return {"code_string": code}
