ATTACKS = {
    "file_write": [
        "open(__SANDBOX_PATH__, 'w').write('x')",
    ],
    "nested_eval": [
        "__import__('builtins').eval('6*7')",
    ],
    "dunder_introspection": [
        "().__class__.__mro__",
    ],
    "dynamic_import": [
        "__import__('math').factorial(5)",
    ],
    "attribute_access": [
        "(1).__class__.__base__",
    ],
}


def make_input(fdp, sandbox):
    import os

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        expr = fdp.PickValueInList(ATTACKS[technique])
        expr = expr.replace(
            "__SANDBOX_PATH__", repr(os.path.join(sandbox, "quiz_marker"))
        )
        if fdp.ConsumeBool():
            expr = "(" + expr + ")"
        if fdp.ConsumeBool():
            expr = " " + expr + " "
    else:
        expr = fdp.PickValueInList([
            "5**3",
            "2 + 3 * 4",
            "(8 - 2) / 3",
            "'quiz'",
            "[1, 2, 3]",
            "True",
        ])

    return {"quiz_expr": expr}
