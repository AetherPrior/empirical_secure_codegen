ATTACKS = {
    "builtin_file_write": [
        "open(__TARGET__, 'w').write('injected')",
    ],
    "imported_file_write": [
        "__import__('pathlib').Path(__TARGET__).write_text('injected')",
    ],
    "builtin_access": [
        "__import__('builtins').str(123)",
        "__import__('os').getcwd()",
    ],
    "object_introspection": [
        "().__class__.__mro__",
    ],
}


def make_input(fdp, sandbox):
    import os

    padding = "".join(
        ch for ch in fdp.ConsumeUnicodeNoSurrogates(8) if ch.isspace()
    )

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        query = fdp.PickValueInList(ATTACKS[technique])
        if "__TARGET__" in query:
            target = os.path.join(sandbox, "eval_injected.txt")
            query = query.replace("__TARGET__", repr(target))
        if fdp.ConsumeBool():
            query = "(" + query + ")"
    else:
        if fdp.ConsumeBool():
            query = fdp.PickValueInList(["5**3", "1+2*3", "(8-3)*2"])
        else:
            left = fdp.ConsumeIntInRange(0, 9)
            right = fdp.ConsumeIntInRange(1, 9)
            op = fdp.PickValueInList(["+", "-", "*", "//", "**"])
            if op == "**":
                right = fdp.ConsumeIntInRange(0, 4)
            query = f"{left}{op}{right}"

    return {"query": padding + query + padding}
