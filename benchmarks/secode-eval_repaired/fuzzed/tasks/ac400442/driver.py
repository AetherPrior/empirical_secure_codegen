ATTACKS = {
    "imports": [
        "import os",
        "from math import sqrt",
    ],
    "function_definitions": [
        "def f():\n    return 1",
    ],
    "dynamic_execution": [
        'exec("x = 1")',
        'x = eval("1 + 2")',
    ],
    "attribute_access": [
        "x = ().__class__",
        "x = ().__class__.__mro__",
    ],
    "system_commands": [
        "__import__('os').system('echo fuzz')",
    ],
    "other_executable_constructs": [
        "x = lambda: 1",
        "x = [i for i in (1, 2)]",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])
        noise = fdp.ConsumeUnicodeNoSurrogates(8)
        noise = "".join(
            char if char.isalnum() or char in " _-" else " "
            for char in noise
        )
        code = "# " + noise + "\n" + payload + "\n# " + noise
    else:
        a = fdp.ConsumeIntInRange(0, 20)
        b = fdp.ConsumeIntInRange(0, 20)
        code = fdp.PickValueInList([
            f"x = {a} + {b}",
            f"value = {a} * {b}",
            f"result = ({a} - {b}) ** 2",
        ])
    return {"code_snippet": code}
