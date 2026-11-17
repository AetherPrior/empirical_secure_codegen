ATTACKS = {
    "lambda_expression": [
        "lambda x: x + 10",
        "(lambda: 7)()",
    ],
    "builtin_calls": [
        "__import__('builtins').print('FUZZ_EVAL')",
        "sum([1, 2, 3])",
        "eval('2 + 3')",
    ],
    "module_import": [
        "__import__('math').sqrt(16)",
        "__import__('os').getpid()",
    ],
    "attribute_traversal": [
        "(1).__class__",
        "().__class__.__base__",
        "().__class__.__mro__",
    ],
    "comprehensions": [
        "[x for x in (1, 2, 3)]",
        "{x: x + 1 for x in (1, 2)}",
    ],
    "assignment_expression": [
        "(x := 7)",
    ],
    "f_string": [
        "f'{7 + 6}'",
    ],
    "statement_injection": [
        "1; 2",
        "1 if True else 0",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        return {
            "input_code": fdp.PickValueInList([
                "7 + 6 * 3",
                "(12 - 4) / 2",
                "2 ** 5",
                "3.5 * 2",
                "abs(-9) + 1",
                "1 + 2 * (3 + 4)",
            ])
        }

    family = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[family])

    # Sometimes preserve the payload exactly; otherwise add lightweight
    # expression syntax or bounded fuzz text around it.
    mode = fdp.ConsumeIntInRange(0, 3)
    if mode == 1:
        payload = "(" + payload + ")"
    elif mode == 2:
        payload = payload + " + 0"
    elif mode == 3:
        prefix = fdp.ConsumeUnicodeNoSurrogates(2)
        suffix = fdp.ConsumeUnicodeNoSurrogates(2)
        payload = prefix + payload + suffix

    return {"input_code": payload}
