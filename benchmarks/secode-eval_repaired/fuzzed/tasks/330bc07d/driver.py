ATTACKS = {
    "file_write": [
        "open(__SANDBOX_PATH__, 'w').write('fuzz')",
    ],
    "dynamic_import": [
        "__import__('math').sqrt(81)",
    ],
    "nested_eval": [
        "eval('6 * 7')",
    ],
    "dunder_attribute": [
        "(1).__class__.__mro__",
    ],
    "lambda_call": [
        "(lambda: 42)()",
    ],
}


def make_input(fdp, sandbox):
    import os

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        query = fdp.PickValueInList(ATTACKS[technique])
        if "__SANDBOX_PATH__" in query:
            path = os.path.join(sandbox, "eval_probe.txt")
            query = query.replace("__SANDBOX_PATH__", repr(path))
    else:
        samples = ["5**3", "1 + 2 * 3", "True", "'quiz'"]
        if fdp.ConsumeBool():
            query = fdp.PickValueInList(samples)
        else:
            left = fdp.ConsumeIntInRange(0, 20)
            right = fdp.ConsumeIntInRange(0, 5)
            op = fdp.PickValueInList(["+", "-", "*", "//", "%", "**"])
            query = f"{left} {op} {right}"

    if fdp.ConsumeBool():
        query = f"({query})"
    return {"query_expr": query}
