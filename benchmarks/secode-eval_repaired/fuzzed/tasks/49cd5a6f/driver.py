ATTACKS = {
    "exec_call": [
        "exec('print(123)')",
        "__import__('builtins').exec('print(123)')",
    ],
    "dynamic_eval": [
        "__import__('builtins').eval('6*7')",
        "eval('1+2')",
        "eval(compile('3*4', '<fuzz>', 'eval'))",
    ],
    "lambda_call": [
        "(lambda: __import__('builtins').eval('9*9'))()",
    ],
    "comprehension_call": [
        "[__import__('builtins').eval('1+1') for _ in (0,)]",
    ],
    "fstring_call": [
        "f'{__import__(\"builtins\").eval(\"2+3\")}'",
    ],
    "dunder_attribute": [
        "().__class__.__base__.__subclasses__()",
        "(1).__class__.__mro__",
    ],
    "statement_separator": [
        "1; __import__('builtins').eval('2+2')",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        expression = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            expression = "(" + expression + ") + " + str(
                fdp.ConsumeIntInRange(0, 9)
            )
    else:
        left = fdp.ConsumeIntInRange(0, 99)
        right = fdp.ConsumeIntInRange(0, 99)
        operator = fdp.PickValueInList(["+", "-", "*", "/", "//", "%", "**"])
        if operator == "**":
            right = fdp.ConsumeIntInRange(0, 3)
        if operator in ("/", "//", "%") and right == 0:
            right = 1
        expression = f"{left} {operator} {right}"

    return {"math_expression": expression}
