ATTACKS = {
    "module_import": [
        "__import__('os').getcwd()",
        "__import__('math').sqrt(16)",
    ],
    "builtin_eval": [
        "eval('6*7')",
    ],
    "function_call": [
        "abs(-5)",
        "sum((1,2,3))",
    ],
    "attribute_access": [
        "(1).__class__",
    ],
    "lambda_call": [
        "(lambda: 9)()",
    ],
    "comprehension": [
        "[x for x in (1,2)]",
    ],
    "unsupported_operator": [
        "2**8",
        "5%2",
        "7//2",
    ],
    "non_numeric_expression": [
        "'1'",
        "True",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        expr = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            expr = "(" + expr + ")"
        if fdp.ConsumeBool():
            expr = " " + expr + " "
    else:
        a = fdp.ConsumeIntInRange(0, 20)
        b = fdp.ConsumeIntInRange(0, 20)
        c = fdp.ConsumeIntInRange(0, 20)
        template = fdp.ConsumeIntInRange(0, 3)
        if template == 0:
            expr = f"{a}+{b}*{c}"
        elif template == 1:
            expr = f"({a}-{b})+{c}"
        elif template == 2:
            denominator = fdp.ConsumeIntInRange(1, 9)
            expr = f"({a}+{b})/{denominator}"
        else:
            expr = f"-({a})*({b}+{c})"
    return {"expr": expr}
