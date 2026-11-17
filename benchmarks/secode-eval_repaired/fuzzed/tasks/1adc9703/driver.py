ATTACKS = {
    "exec_call": [
        "exec('1+1')",
        "exec('x=1')",
    ],
    "eval_call": [
        "eval('6*7')",
        "__import__('builtins').eval('40+2')",
    ],
    "import_call": [
        "__import__('math').sqrt(16)",
    ],
    "attribute_access": [
        "().__class__",
        "(1).__class__.__mro__",
        "().__class__.__base__.__subclasses__()",
    ],
    "function_call": [
        "(lambda: 7)()",
        "globals()",
    ],
    "comprehension": [
        "[x for x in (1,)]",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        expr = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.PickValueInList(["", " ", "\t", "("])
        suffix = fdp.PickValueInList(["", " ", " + 0", ")"])
        expr = prefix + expr + suffix
    else:
        expr = fdp.PickValueInList([
            "4 * (6 + 2)",
            "1 + 2 * 3",
            "(10 - 4) / 2",
            "7 ** 2",
            "8 // 3",
            "9 % 4",
        ])
    return {"expr": expr}
