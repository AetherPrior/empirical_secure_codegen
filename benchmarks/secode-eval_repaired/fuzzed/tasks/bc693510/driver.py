ATTACKS = {
    "imports": [
        "import os",
        "from math import sqrt",
        "import os\nos.getcwd()",
    ],
    "definitions": [
        "def f():\n    return 1",
        "class C:\n    pass",
        "x = lambda: 1",
    ],
    "dynamic_execution": [
        "x = __import__('os')",
        "x = eval('1 + 1')",
        "exec('x = 1')",
        "x = compile('1 + 1', '<string>', 'eval')",
    ],
    "file_access": [
        "x = open('example.txt', 'w')",
    ],
    "introspection": [
        "x = (1).__class__",
        "x = getattr(1, '__class__')",
    ],
    "comprehensions": [
        "x = [i for i in (1, 2)]",
        "x = {i: i for i in (1, 2)}",
    ],
    "system_command": [
        "import os\nos.system('echo fuzz')",
        "x = __import__('os').system('echo fuzz')",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        snippet = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            snippet = "a = 1 + 2\n" + snippet
        if fdp.ConsumeBool():
            snippet += "\nb = 3 * 4"
    else:
        samples = [
            "a = 2 + 3",
            "x = 7",
            "a = 4 * 5\nb = a - 3",
            "x = (1 + 2) * 3",
        ]
        snippet = fdp.PickValueInList(samples)
    return {"python_snippet": snippet}
