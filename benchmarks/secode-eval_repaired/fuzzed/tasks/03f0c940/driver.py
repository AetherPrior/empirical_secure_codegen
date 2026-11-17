ATTACKS = {
    "builtin_import": [
        "__import__('os').getcwd()",
        "__import__('builtins').eval('1+1')",
    ],
    "dunder_introspection": [
        "().__class__.__mro__",
        "().__class__.__base__.__subclasses__()",
    ],
    "file_write": [
        "open({path}, 'w').write('hacked')",
        "__import__('pathlib').Path({path}).write_text('hacked')",
    ],
    "dynamic_execution": [
        "__import__('builtins').exec(\"open({path}, 'w').write('hacked')\")",
    ],
}


def make_input(fdp, sandbox):
    import os

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        target = os.path.join(sandbox, "quiz_output.txt")
        payload = payload.format(path=repr(target))
        prefix = fdp.PickValueInList(["", " ", "\n"])
        suffix = fdp.PickValueInList(["", " ", "\n"])
        quiz_query = prefix + payload + suffix
    else:
        quiz_query = fdp.PickValueInList(
            ["5**3", "1+2", "len('quiz')", str(fdp.ConsumeIntInRange(0, 100))]
        )

    return {"quiz_query": quiz_query}
