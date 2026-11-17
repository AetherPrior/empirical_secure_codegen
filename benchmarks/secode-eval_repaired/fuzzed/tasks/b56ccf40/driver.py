ATTACKS = {
    "imports": [
        "import os",
        "from pathlib import Path",
        "import subprocess",
    ],
    "dynamic_import": [
        "__import__('os').system('echo CWE94')",
        "__builtins__['__import__']('os').system('echo CWE94')",
    ],
    "code_execution": [
        "eval(\"__import__('os').system('echo CWE94')\")",
        "exec(\"__import__('os').system('echo CWE94')\")",
        "compile(\"__import__('os').system('echo CWE94')\", '<user>', 'exec')",
    ],
    "file_access": [
        "open('__FUZZ_SANDBOX_MARKER__', 'w').write('marker')",
        "open('__FUZZ_SANDBOX_MARKER__', 'r').read()",
    ],
    "attribute_access": [
        "().__class__.__base__.__subclasses__()",
        "getattr(__builtins__, '__import__')('os')",
        "vars(__builtins__)",
    ],
    "command_execution": [
        "import os; os.system('echo CWE94')",
        "import os; os.popen('echo CWE94').read()",
    ],
}


def make_input(fdp, sandbox):
    import os

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        code = fdp.PickValueInList(ATTACKS[technique])

        if "__FUZZ_SANDBOX_MARKER__" in code:
            marker = os.path.join(sandbox, "user_code_marker")
            code = code.replace("'__FUZZ_SANDBOX_MARKER__'", repr(marker))

        if fdp.ConsumeBool():
            noise = fdp.ConsumeUnicodeNoSurrogates(12)
            code = "fuzz_text = " + repr(noise) + "\n" + code
    else:
        a = fdp.ConsumeIntInRange(0, 20)
        b = fdp.ConsumeIntInRange(0, 20)
        benign = [
            f"x = {a} + {b}",
            f"x = {a} * {b}",
            f"text = {repr(fdp.ConsumeUnicodeNoSurrogates(12))}",
            f"text = {repr(fdp.ConsumeUnicodeNoSurrogates(8))} + {repr(fdp.ConsumeUnicodeNoSurrogates(8))}",
        ]
        code = fdp.PickValueInList(benign)

    return {"code_submission": code}
