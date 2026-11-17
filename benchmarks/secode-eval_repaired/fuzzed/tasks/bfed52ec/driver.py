ATTACKS = {
    "direct_call": [
        "exec('print(10)')",
        "print(10)",
    ],
    "nested_eval": [
        "eval('2 + 3')",
    ],
    "import_call": [
        "__import__('math').sqrt(16)",
    ],
    "dunder_attribute": [
        "(1).__class__",
        "().__class__.__mro__",
    ],
    "lambda_call": [
        "(lambda: 7)()",
    ],
    "comprehension": [
        "[x for x in (1, 2)]",
    ],
    "sandbox_file_write": [
        "open(__SANDBOX__ + '/eval_marker', 'w').write('x')",
    ],
}

def make_input(fdp, sandbox):
    benign = [
        "4 * (6 + 2)",
        "1 + 2 * 3",
        "(12 - 4) / 2",
        "2 ** 5",
        "7 % 3",
        "1 < 2",
        "True and False",
    ]

    if not fdp.ConsumeBool():
        formula = fdp.PickValueInList(benign)
        if fdp.ConsumeBool():
            formula = f"({formula}) + {fdp.ConsumeIntInRange(0, 9)}"
        return {"formula": formula}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])
    if "__SANDBOX__" in payload:
        payload = payload.replace("__SANDBOX__", repr(sandbox))

    formula = f"({payload})"
    if fdp.ConsumeBool():
        operator = fdp.PickValueInList(["+", "*", "-", "and", "or"])
        value = fdp.ConsumeIntInRange(0, 5)
        formula = f"({formula}) {operator} {value}"
    return {"formula": formula}
