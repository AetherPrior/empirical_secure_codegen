ATTACKS = {
    "function_calls": [
        "abs(-3)",
        "__import__('builtins').print(7)",
    ],
    "module_imports": [
        "__import__('math').sqrt(16)",
    ],
    "attribute_access": [
        "(1).__class__",
        "().__class__",
    ],
    "extra_operators": [
        "2 ** 3",
        "5 // 2",
        "7 % 4",
    ],
    "names": [
        "a",
        "__builtins__",
    ],
    "comprehensions_and_containers": [
        "[x for x in (1,)]",
        "{1: 2}",
    ],
    "statement_injection": [
        "1; print(7)",
        "1\nprint(7)",
    ],
    "lambda_calls": [
        "(lambda: 9)()",
    ],
    "subscripts": [
        "(1, 2)[0]",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        expr = fdp.PickValueInList(ATTACKS[family])
        prefix = fdp.PickValueInList(["", " ", "\n"])
        suffix = fdp.PickValueInList(["", " ", "\n"])
        expr = prefix + expr + suffix
    else:
        a = fdp.ConsumeIntInRange(0, 20)
        b = fdp.ConsumeIntInRange(1, 20)
        c = fdp.ConsumeIntInRange(0, 20)
        op = fdp.PickValueInList(["+", "-", "*", "/"])
        if op == "/":
            expr = f"({a} + {c}) / {b}"
        else:
            expr = f"({a} {op} {c}) + {b}"

    return {"math_expr": expr}
