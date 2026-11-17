ATTACKS = {
    "identifier": [
        "a + 3",
        "__builtins__",
    ],
    "imports_and_calls": [
        "__import__('os').getcwd()",
        "__import__('pathlib').Path($SANDBOX + '/eval_marker').write_text('x')",
        "open($SANDBOX + '/eval_marker', 'w').write('x')",
    ],
    "attribute_access": [
        "().__class__.__mro__",
        "().__class__.__bases__",
    ],
    "lambda_and_comprehension": [
        "(lambda: 7)()",
        "[x for x in (1, 2, 3)]",
    ],
    "string_and_subscript": [
        "'abc'[0]",
        "'abc'.upper()",
    ],
    "unsupported_operators": [
        "2 ** 8",
        "7 // 2",
        "7 % 3",
    ],
    "statement_injection": [
        "1; __import__('pathlib').Path($SANDBOX + '/eval_marker').write_text('x')",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        expr = fdp.PickValueInList(ATTACKS[technique])
        expr = expr.replace("$SANDBOX", repr(sandbox))
        if fdp.ConsumeBool():
            expr = "(" + expr + ")"
        if fdp.ConsumeBool():
            expr = "\t " + expr + " \n"
        return {"expr": expr}

    if fdp.ConsumeBool():
        return {"expr": fdp.PickValueInList([
            "10 / 2 + 3",
            "1 + 2 * 3",
            "((8 - 3) * 2) / 5",
            "-4 + 9",
        ])}

    a = fdp.ConsumeIntInRange(0, 20)
    b = fdp.ConsumeIntInRange(1, 20)
    c = fdp.ConsumeIntInRange(0, 20)
    op1 = fdp.PickValueInList(["+", "-", "*", "/"])
    op2 = fdp.PickValueInList(["+", "-", "*", "/"])
    return {"expr": f"({a} {op1} {b}) {op2} {c}"}
