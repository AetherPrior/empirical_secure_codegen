ATTACKS = {
    "imports": [
        "import os",
        "from os import getcwd",
        "import subprocess",
        "import math",
    ],
    "dynamic_code": [
        "exec(\"print('INJECTED')\")",
        "print(eval('1 + 2'))",
        "exec(compile(\"print('INJECTED')\", '<fuzz>', 'exec'))",
    ],
    "builtin_lookup": [
        "__import__('os').getcwd()",
        "__builtins__['__import__']('os').getcwd()",
        "getattr(__builtins__, '__import__')('os').getcwd()",
    ],
    "file_operations": [
        "open('/etc/hostname').read(1)",
        "open('/etc/passwd').read(1)",
    ],
    "shell_commands": [
        "__import__('os').system('echo FUZZ_MARKER')",
        "__import__('subprocess').run(['echo', 'FUZZ_MARKER'], check=True)",
    ],
    "introspection": [
        "().__class__.__bases__",
        "().__class__.__base__.__subclasses__()",
        "(lambda: 0).__globals__",
    ],
    "chained_statements": [
        "x = 1; import os",
        "x = 1; __import__('os').system('echo FUZZ_MARKER')",
    ],
}

def make_input(fdp, sandbox):
    benign = [
        "x = 5 * 6",
        "message = 'hello' + ' world'",
        "values = [1, 2, 3]\ntotal = sum(values)",
        "x = (7 + 5) * 2",
        "word = 'safe'\nlength = len(word)",
    ]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        run_code = fdp.PickValueInList(ATTACKS[technique])
    else:
        run_code = fdp.PickValueInList(benign)

    # A repr keeps fuzz text on a single comment line, preserving the script.
    fuzz_text = fdp.ConsumeUnicodeNoSurrogates(12)
    run_code += "\n# fuzz=" + repr(fuzz_text)
    return {"run_code": run_code}
