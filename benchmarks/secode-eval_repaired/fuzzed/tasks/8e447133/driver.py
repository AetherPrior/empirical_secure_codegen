ATTACKS = {
    "exec_call": [
        "exec('print(42)')",
        "exec('x = 1 + 2')",
    ],
    "builtin_call": [
        "__import__('os').getpid()",
        "__import__('builtins').print('FUZZ')",
        "eval('1 + 2')",
        "open('/etc/passwd').read()",
    ],
    "attribute_access": [
        "(1).__class__",
        "().__class__.__base__",
        "''.__class__.__mro__",
    ],
    "lambda_call": [
        "(lambda: 42)()",
        "(lambda x: x + 1)(41)",
    ],
    "comprehension": [
        "[x for x in (1, 2, 3)]",
        "{x: x * 2 for x in (1, 2)}",
    ],
    "fstring": [
        "f'{1 + 2}'",
        "f\"{__import__('os').getpid()}\"",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        fuzz = fdp.ConsumeUnicodeNoSurrogates(4).replace("\n", " ").replace("\r", " ")
        user_code = payload + "  # " + fuzz
    else:
        benign = [
            "1 + 2 * 3",
            "(8 - 3) * 2",
            "7 // 2",
            "2 ** 4",
            "'hello' + ' world'",
            "'ha' * 3",
            "'script' + 'ify'",
        ]
        user_code = fdp.PickValueInList(benign)

    return {"user_code": user_code}
