ATTACKS = {
    "imports": [
        "import sys",
        "from math import sqrt",
    ],
    "definitions": [
        "def f():\n    return 1",
        "class C:\n    pass",
    ],
    "dynamic_evaluation": [
        "x = eval('1 + 2')",
        "exec('x = 1')",
    ],
    "introspection": [
        "x = __builtins__",
        "x = ().__class__.__base__",
        "x = getattr((), '__class__')",
    ],
    "system_command": [
        "x = __import__('os').system('true')",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        code = fdp.PickValueInList(ATTACKS[technique])

        # Keep fuzz text in comments so the selected attack remains intact.
        noise = fdp.ConsumeUnicodeNoSurrogates(12).replace("\n", " ").replace("\r", " ")
        if fdp.ConsumeBool():
            code = "# " + noise + "\n" + code
        if fdp.ConsumeBool():
            code = code.rstrip() + "\n# " + noise
    else:
        left = fdp.ConsumeIntInRange(-20, 20)
        right = fdp.ConsumeIntInRange(-20, 20)
        code = fdp.PickValueInList([
            f"p = {left} + {right}",
            f"value = {left} * {right}",
            f"a = {left}\nb = a - ({right})",
            f"result = ({left} + {right}) // 2",
        ])

    return {"user_code": code}
