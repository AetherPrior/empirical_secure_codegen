ATTACKS = {
    "exec_call": [
        "exec('print(10)')",
        "__import__('builtins').exec('print(10)')",
    ],
    "nested_eval": [
        "eval('1 + 2')",
        "__import__('builtins').eval('6 * 7')",
    ],
    "import_call": [
        "__import__('math').sqrt(16)",
        "__import__('os').getcwd()",
    ],
    "dunder_introspection": [
        "().__class__.__mro__",
        "(1).__class__.__name__",
    ],
    "callable_expression": [
        "(lambda: 7)()",
        "(lambda x: x * x)(9)",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        user_input = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            user_input = "(" + user_input + ")"
        if fdp.ConsumeBool():
            user_input += fdp.PickValueInList(["", " ", "\t", "\n"])
    else:
        if fdp.ConsumeBool():
            user_input = fdp.PickValueInList([
                "4 * (6 + 2)",
                "1 + 2 * 3",
                "(10 - 4) / 2",
                "2 ** 5",
            ])
        else:
            a = fdp.ConsumeIntInRange(0, 20)
            b = fdp.ConsumeIntInRange(0, 20)
            c = fdp.ConsumeIntInRange(0, 20)
            user_input = f"{a} * ({b} + {c})"

    return {"user_input": user_input}
