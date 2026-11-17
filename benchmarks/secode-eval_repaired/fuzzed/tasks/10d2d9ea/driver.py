ATTACKS = {
    "bare_name": ["a + 3", "__builtins__"],
    "function_call": ["abs(-7)", "sum([1, 2])"],
    "module_import": [
        "__import__('math').sqrt(16)",
        "__import__('os').getcwd()",
    ],
    "attribute_access": ["(1).__class__", "().__class__.__mro__"],
    "container_access": ["[10, 20][0]", "{'x': 3}['x']"],
    "lambda_expression": ["(lambda: 6)()", "(lambda x: x + 1)(2)"],
    "comprehension": ["[x for x in [1]][0]", "sum(x for x in [1, 2])"],
    "string_expression": ["'2' * 3", "'x'"],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        expression = fdp.PickValueInList(ATTACKS[technique])

        # Optionally surround the payload with small arithmetic fragments.
        if fdp.ConsumeBool():
            expression = fdp.PickValueInList(["", "1 + ", "2 * ", " ", "("]) + expression
        if fdp.ConsumeBool():
            expression += fdp.PickValueInList(["", " + 1", " * 2", " ", ")"])
    else:
        expression = fdp.PickValueInList([
            "10 / 2 + 3",
            "1 + 2 * 3",
            "(8 - 2) / 3",
            "0",
            "7 - 4",
        ])

    return {"expression": expression}
