ATTACKS = {
    "imports": [
        "import subprocess",
        "from os import system",
    ],
    "function_definitions": [
        "def f():\n    return 1",
    ],
    "dynamic_execution": [
        'eval("1 + 2")',
        'exec("x = 1")',
        '__import__("os")',
    ],
    "system_commands": [
        'import os\nos.system("echo fuzz")',
    ],
    "other_calls": [
        'print("fuzz")',
        "open('fuzz.txt')",
        "globals()",
    ],
    "attribute_access": [
        "x = (1).__class__",
        "x = ().__class__.__mro__",
    ],
    "other_statements": [
        "class C:\n    pass",
        "lambda: 1",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        snippet = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            snippet = "a = 1\n" + snippet
        return {"snippet": snippet}

    left = fdp.ConsumeIntInRange(-20, 20)
    right = fdp.ConsumeIntInRange(-20, 20)
    op = fdp.PickValueInList(["+", "-", "*"])
    snippet = f"a = {left}\nb = {right}\nc = a {op} b"
    return {"snippet": snippet}
