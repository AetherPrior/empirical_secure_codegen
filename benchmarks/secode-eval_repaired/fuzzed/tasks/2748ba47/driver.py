ATTACKS = {
    "import_statement": [
        "import os",
        "from pathlib import Path",
    ],
    "dynamic_import": [
        "__import__('os').getcwd()",
        "importlib = __import__('importlib')",
    ],
    "file_access": [
        "open('fuzz_missing_file.txt', 'r').read()",
        "open('/dev/null', 'r').read()",
    ],
    "shell_command": [
        "__import__('os').system('echo fuzz')",
        "import os; os.system('echo fuzz')",
    ],
    "dynamic_execution": [
        "eval('1 + 2')",
        "exec('x = 1')",
        "exec(compile('x = 1', '<fuzz>', 'exec'))",
    ],
    "builtins_access": [
        "globals()",
        "getattr(__builtins__, 'eval')('1 + 2')",
    ],
    "dunder_introspection": [
        "().__class__.__base__.__subclasses__()",
        "().__class__.__mro__",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        script = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            # Keep fuzz text in a comment so it cannot alter the chosen payload.
            text = fdp.ConsumeUnicodeNoSurrogates(12).replace("\n", " ").replace("\r", " ")
            script = "# " + text + "\n" + script
        return {"script_to_execute": script}

    benign = [
        "x = 5 * 6",
        "result = (2 + 3) * 4",
        "message = 'hello'.upper()",
        "values = [1, 2, 3]",
    ]
    script = fdp.PickValueInList(benign)
    if fdp.ConsumeBool():
        text = fdp.ConsumeUnicodeNoSurrogates(12)
        script += "\nlabel = " + repr(text)
    return {"script_to_execute": script}
