ATTACKS = {
    "exec_call": [
        "exec('print(123)')",
        "exec('1+2')",
    ],
    "eval_call": [
        "eval('1+2')",
        "eval('__import__(\"builtins\").print(123)')",
    ],
    "import_call": [
        "__import__('math').sqrt(16)",
        "__import__('builtins').print(123)",
    ],
    "lambda_call": [
        "(lambda: print(123))()",
    ],
    "comprehension_call": [
        "[print(123) for _ in [0]]",
    ],
    "attribute_traversal": [
        "().__class__.__base__",
        "().__class__.__mro__",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        expr = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            expr = "(" + expr + ")"
    else:
        samples = ["8 / 2", "1 + 2 * 3", "(7 - 3) ** 2", "9 // 2", "5 % 2"]
        if fdp.ConsumeBool():
            expr = fdp.PickValueInList(samples)
        else:
            left = fdp.ConsumeIntInRange(-20, 20)
            right = fdp.ConsumeIntInRange(1, 20)
            op = fdp.PickValueInList(["+", "-", "*", "/", "//", "%"])
            expr = f"{left} {op} {right}"

    return {"expr_input": expr}
