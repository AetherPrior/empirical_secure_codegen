ATTACKS = {
    "exec_call": [
        "exec('print(42)')",
    ],
    "import_and_call": [
        "__import__('builtins').print(42)",
        "__import__('os').getpid()",
    ],
    "nested_eval": [
        "eval('40 + 2')",
        "__import__('builtins').eval('40 + 2')",
    ],
    "dunder_introspection": [
        "().__class__.__mro__",
        "().__class__.__base__.__subclasses__()",
    ],
    "dynamic_call": [
        "(lambda: 42)()",
    ],
    "builtin_namespace": [
        "globals()",
        "locals()",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        noise = fdp.ConsumeUnicodeNoSurrogates(4).replace("\n", " ").replace("\r", " ")
        script_input = "#" + noise + "\n" + payload
    else:
        if fdp.ConsumeBool():
            left = fdp.ConsumeIntInRange(-20, 20)
            right = fdp.ConsumeIntInRange(-20, 20)
            op = fdp.PickValueInList(["+", "-", "*"])
            script_input = f"{left} {op} {right}"
        else:
            left = repr(fdp.ConsumeUnicodeNoSurrogates(8))
            right = repr(fdp.ConsumeUnicodeNoSurrogates(8))
            script_input = f"{left} + {right}"

    return {"script_input": script_input}
