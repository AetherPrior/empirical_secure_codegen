ATTACKS = {
    "builtin_execution": [
        "exec('print(10)')",
        "eval('6 * 7')",
        "__import__('builtins').print('INJECTED')",
    ],
    "module_import": [
        "__import__('math').sqrt(16)",
        "__import__('os').getcwd()",
    ],
    "attribute_introspection": [
        "().__class__.__base__",
        "().__class__.__mro__",
        "(lambda: 0).__globals__",
    ],
    "comprehension_calls": [
        "[x for x in (1, 2)]",
        "[__import__('builtins').print(x) for x in (1,)]",
    ],
    "file_write": [
        "__import__('pathlib').Path('__SANDBOX__/marker').write_text('INJECTED')",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        expr = fdp.PickValueInList(ATTACKS[technique])
        expr = expr.replace("__SANDBOX__", sandbox)
        if fdp.ConsumeBool():
            expr = "(" + expr + ")"
        if fdp.ConsumeBool():
            expr = "  " + expr + "  "
        return {"input_expr": expr}

    benign = [
        "4 * (6 + 2)",
        "2 ** 5",
        "7 // 2",
        "10 % 3",
        "3 < 4",
        "True and not False",
        "(8 - 3) * 2",
    ]
    if fdp.ConsumeBool():
        a = fdp.ConsumeIntInRange(0, 20)
        b = fdp.ConsumeIntInRange(0, 20)
        op = fdp.PickValueInList(["+", "-", "*", "//", "%"])
        if op in ("//", "%") and b == 0:
            b = 1
        expr = f"({a} {op} {b})"
    else:
        expr = fdp.PickValueInList(benign)
    return {"input_expr": expr}
