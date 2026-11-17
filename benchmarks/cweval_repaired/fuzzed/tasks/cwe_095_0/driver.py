ATTACKS = {
    "identifier_literals": ["True", "False", "None"],
    "string_literals": ["'x'", "'a' + 'b'"],
    "function_calls": ["abs(-7)", "pow(2, 3)", "len(())"],
    "conditional_expression": ["1 if True else 0"],
    "attribute_access": ["(1).__class__", "().__class__.__name__"],
    "container_literals": ["[1, 2]", "{1: 2}", "{1, 2}"],
    "comprehensions": ["[x for x in (1,)]"],
    "lambda_expression": ["(lambda: 7)()"],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        expr = fdp.PickValueInList(ATTACKS[technique])
        # Add fuzz-derived whitespace without changing the payload's syntax.
        padding = " " * len(fdp.ConsumeUnicodeNoSurrogates(4))
        expr = padding + expr + padding
    else:
        a = fdp.ConsumeIntInRange(0, 20)
        b = fdp.ConsumeIntInRange(1, 20)
        expr = fdp.PickValueInList([
            f"{a}+{b}",
            f"{a}*{b}",
            f"({a}+{b})/2",
            f"{a}-{b}",
        ])

    return {"expr": expr}
