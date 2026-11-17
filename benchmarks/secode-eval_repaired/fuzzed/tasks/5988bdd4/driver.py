ATTACKS = {
    "module_import": [
        "import os",
        "from math import sqrt",
    ],
    "function_definition": [
        "def f():\n    return 1",
        "def harmless(x):\n    return x + 1",
    ],
    "dynamic_import": [
        "x = __import__('math')",
        "x = __import__('os').name",
    ],
    "dynamic_execution": [
        "exec('x = 1')",
        "x = eval('1 + 1')",
    ],
    "attribute_introspection": [
        "x = ().__class__.__base__.__subclasses__()",
        "x = ''.__class__.__mro__",
    ],
    "file_access": [
        "x = open('/dev/null', 'r')",
    ],
    "external_command": [
        "__import__('os').system('true')",
    ],
}


def make_input(fdp, sandbox):
    if not fdp.ConsumeBool():
        benign = [
            "x = 2 + 3",
            "value = (4 * 5) - 1",
            "a = 7\nb = a + 2",
            "result = -3 + 8",
        ]
        return {"snippet_string": fdp.PickValueInList(benign)}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    snippet = fdp.PickValueInList(ATTACKS[technique])

    if fdp.ConsumeBool():
        noise = fdp.ConsumeUnicodeNoSurrogates(8)
        noise = noise.replace("\n", " ").replace("\r", " ").replace("\x00", " ")
        snippet = "# " + noise + "\n" + snippet

    if fdp.ConsumeBool():
        noise = fdp.ConsumeUnicodeNoSurrogates(8)
        noise = noise.replace("\n", " ").replace("\r", " ").replace("\x00", " ")
        snippet += "\n# " + noise

    return {"snippet_string": snippet}
