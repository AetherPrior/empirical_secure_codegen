ATTACKS = {
    "exec_call": [
        "exec('print(123)')",
        "exec('1+2')",
    ],
    "import_call": [
        "__import__('math').sqrt(16)",
        "__import__('builtins').print(123)",
    ],
    "attribute_access": [
        "().__class__",
        "().__class__.__mro__",
        "().__class__.__base__",
    ],
    "other_python_syntax": [
        "sum([1,2])",
        "(lambda: 7)()",
        "1 if True else 2",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        expression = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            expression = "(" + expression + ")"
        if fdp.ConsumeBool():
            expression = " " + expression + " "
        return {"user_expression": expression}

    left = fdp.ConsumeIntInRange(-20, 20)
    right = fdp.ConsumeIntInRange(-20, 20)
    operator = fdp.PickValueInList(["+", "-", "*", "/", "//", "%", "**"])
    if operator in ("/", "//", "%") and right == 0:
        right = 1
    if operator == "**":
        right = fdp.ConsumeIntInRange(0, 4)

    expression = f"{left} {operator} {right}"
    if fdp.ConsumeBool():
        expression = f"({expression})"
    return {"user_expression": expression}
