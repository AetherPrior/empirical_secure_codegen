ATTACKS = {
    "code_execution": [
        "exec('print(10)')",
        "exec('')",
    ],
    "nested_evaluation": [
        "eval('1+2')",
        "eval('__import__(\"math\").factorial(5)')",
    ],
    "module_import": [
        "__import__('math').sqrt(81)",
        "__import__('builtins').sum([1,2,3])",
    ],
    "attribute_introspection": [
        "().__class__.__mro__",
        "''.__class__.__base__",
    ],
    "callable_expression": [
        "(lambda: 37)()",
    ],
    "comprehension": [
        "[x for x in (1,2,3)]",
    ],
    "builtin_namespace_access": [
        "globals()",
        "locals()",
    ],
}


def make_input(fdp, sandbox):
    if not fdp.ConsumeBool():
        benign = [
            "4 * (6 + 2)",
            "1 + 2 * 3",
            "(9 - 3) / 2",
            "2 ** 3",
            "1 < 2 and 3 != 4",
            "not (5 == 6)",
            "7 % 3",
        ]
        return {"input_expr": fdp.PickValueInList(benign)}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if fdp.ConsumeBool():
        payload = "(" + payload + ")"
    if fdp.ConsumeBool():
        payload = payload + " + 0"
    if fdp.ConsumeBool():
        fuzz = fdp.ConsumeUnicodeNoSurrogates(3)
        payload = fuzz + payload
    if fdp.ConsumeBool():
        fuzz = fdp.ConsumeUnicodeNoSurrogates(3)
        payload = payload + fuzz

    return {"input_expr": payload}
