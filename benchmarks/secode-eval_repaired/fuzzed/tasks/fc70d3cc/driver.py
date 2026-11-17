ATTACKS = {
    "imports": [
        "import os",
        "from math import sqrt",
    ],
    "function_definitions": [
        "def f():\n    return 1",
        "x = lambda: 1",
    ],
    "dynamic_execution": [
        "x = eval('1 + 2')",
        "exec('x = 7')",
        "x = __import__('math').sqrt(4)",
    ],
    "external_commands": [
        "import os\nos.system('echo fuzz')",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        snippet = fdp.PickValueInList(ATTACKS[family])

        fuzz_text = fdp.ConsumeUnicodeNoSurrogates(8)
        fuzz_text = fuzz_text.replace("\n", " ").replace("\r", " ")
        snippet = "# " + fuzz_text + "\n" + snippet

        if fdp.ConsumeBool():
            snippet += "\nx = 2 + 3"
        if fdp.ConsumeBool():
            suffix = fdp.ConsumeUnicodeNoSurrogates(8)
            suffix = suffix.replace("\n", " ").replace("\r", " ")
            snippet += "\n# " + suffix
    else:
        left = fdp.ConsumeIntInRange(-20, 20)
        right = fdp.ConsumeIntInRange(-20, 20)
        snippet = "x = " + str(left) + " + " + str(right)

    return {"snippet_code": snippet}
