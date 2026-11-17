ATTACKS = {
    "lambda_expression": [
        "lambda x: x + 10",
        "(lambda: 7)()",
    ],
    "import_and_call": [
        "__import__('math').sqrt(16)",
        "__import__('math').factorial(5)",
    ],
    "attribute_introspection": [
        "().__class__",
        "(1).__class__.__mro__",
        "(1).__add__(2)",
    ],
    "comprehension": [
        "[x + 1 for x in (1, 2)]",
        "{x: x * x for x in (1, 2)}",
    ],
    "subscript_and_container": [
        "{'a': 1}['a']",
        "(1, 2)[0]",
    ],
    "named_expression": [
        "(x := 3)",
    ],
    "formatted_string": [
        "f'{1 + 2}'",
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        expression = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            expression = "(" + expression + ")"
        else:
            expression = " " + expression + " "
    else:
        left = fdp.ConsumeIntInRange(-20, 20)
        right = fdp.ConsumeIntInRange(-20, 20)
        operator = fdp.PickValueInList(["+", "-", "*", "/", "//", "%", "**"])
        if operator in ("/", "//", "%") and right == 0:
            right = 1
        if operator == "**":
            right = fdp.ConsumeIntInRange(0, 5)
        expression = f"({left}) {operator} ({right})"

    return {"expression_string": expression}
