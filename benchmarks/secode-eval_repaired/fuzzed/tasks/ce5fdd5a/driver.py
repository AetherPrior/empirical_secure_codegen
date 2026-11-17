ATTACKS = {
    "builtin_call": [
        "__import__('builtins').len((1, 2, 3))",
    ],
    "attribute_introspection": [
        "().__class__.__mro__",
    ],
    "nested_evaluation": [
        "__import__('builtins').eval('6*7')",
        '__import__("builtins").exec("1+1")',
    ],
    "comprehension": [
        "[x*x for x in (1, 2)]",
    ],
    "file_write": [
        "open({path}, 'w').write('fuzzed')",
    ],
}


def make_input(fdp, sandbox):
    import os

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        expr = fdp.PickValueInList(ATTACKS[technique])
        if "{path}" in expr:
            expr = expr.format(
                path=repr(os.path.join(sandbox, "eval_injection.txt"))
            )
        if fdp.ConsumeBool():
            expr = "(" + expr + ")"
        if fdp.ConsumeBool():
            expr = " \t" + expr + "\n"
    else:
        benign = [
            "5**3",
            "2 + 3 * 4",
            "-7",
            "1/2",
            "0x10",
            "True",
        ]
        if fdp.ConsumeBool():
            expr = fdp.PickValueInList(benign)
        else:
            a = fdp.ConsumeIntInRange(0, 20)
            b = fdp.ConsumeIntInRange(0, 20)
            expr = "{} + {} * 2".format(a, b)

    return {"expr": expr}
