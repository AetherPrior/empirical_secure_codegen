ATTACKS = {
    "exec_call": [
        "exec('print(42)')",
        "exec('1 + 2')",
        "exec(\"__import__('os').getpid()\")",
    ],
    "dynamic_import": [
        "__import__('os').getpid()",
        "__import__('math').sqrt(49)",
        "__import__('builtins').eval('6 * 7')",
    ],
    "attribute_access": [
        "(1).__class__",
        "().__class__.__base__",
        "''.__class__.__mro__",
    ],
    "call_expression": [
        "abs(-7)",
        "sum((1, 2, 3))",
        "(lambda: 42)()",
    ],
    "comprehension": [
        "[x * x for x in (1, 2, 3)]",
        "{x: x + 1 for x in (1, 2)}",
    ],
    "format_method": [
        "'{0.__class__}'.format(1)",
        "'{0}'.format(6 * 7)",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        script = fdp.PickValueInList(ATTACKS[technique])

        # Optional harmless framing and fuzz text around the attack expression.
        if fdp.ConsumeBool():
            script = "(" + script + ")"
        if fdp.ConsumeBool():
            script = fdp.PickValueInList([" ", "\n", "\t"]) + script
        if fdp.ConsumeBool():
            script += fdp.PickValueInList([" ", "\n", "  # fuzz"])
    else:
        script = fdp.PickValueInList([
            "1 + 2 * 3",
            "(8 - 3) * 2",
            "7 / 2",
            "'hello' + ' world'",
            "'ha' * 3",
            "'x' + str(2)",
        ])

    return {"script_str": script}
