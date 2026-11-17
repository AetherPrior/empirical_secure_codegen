ATTACKS = {
    "direct_builtin_call": [
        "open({path!r}, 'w').write('eval-injection')",
        "__builtins__['open']({path!r}, 'w').write('eval-injection')",
    ],
    "builtin_import": [
        "__import__('builtins').open({path!r}, 'w').write('eval-injection')",
    ],
    "dunder_attribute_traversal": [
        "().__class__.__mro__[1].__subclasses__()",
    ],
}

def make_input(fdp, sandbox):
    import os

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        query = payload.format(path=os.path.join(sandbox, "marker.txt"))
        if fdp.ConsumeBool():
            query = "(" + query + ")"
    else:
        query = fdp.PickValueInList([
            "5**3",
            "1 + 2 * 3",
            "(8 - 3) / 5",
            "2 ** 4 + 1",
            "-7 % 3",
        ])

    return {"query_str": query}
