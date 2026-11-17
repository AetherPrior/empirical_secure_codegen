ATTACKS = {
    "module_import": [
        "import os",
        "import subprocess",
        "from pathlib import Path",
    ],
    "file_io": [
        "open('__FUZZ_SANDBOX__/marker.txt').read()",
        "open('__FUZZ_SANDBOX__/marker.txt', 'w').write('changed')",
    ],
    "dynamic_execution": [
        "exec(\"x = 1\")",
        "eval(\"__import__('os').getcwd()\")",
        "exec(compile('x = 1', '<user>', 'exec'))",
    ],
    "command_execution": [
        "import os\nos.system('echo fuzz')",
        "import subprocess\nsubprocess.run(['echo', 'fuzz'])",
    ],
    "attribute_escape": [
        "().__class__.__base__.__subclasses__()",
        "getattr(().__class__, '__base__')",
    ],
    "builtin_access": [
        "__builtins__",
        "globals()",
        "locals()",
    ],
}


def make_input(fdp, sandbox):
    import os

    marker = os.path.join(sandbox, "marker.txt")
    with open(marker, "w", encoding="utf-8") as f:
        f.write("marker")

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])
        payload = payload.replace("__FUZZ_SANDBOX__", sandbox)

        if fdp.ConsumeBool():
            prefix = "# " + fdp.ConsumeUnicodeNoSurrogates(8) + "\n"
            payload = prefix + payload
        if fdp.ConsumeBool():
            payload += "\n# " + fdp.ConsumeUnicodeNoSurrogates(8)
        script = payload
    else:
        script = fdp.PickValueInList([
            "x = 5 * 6",
            "message = 'hello' + ' world'",
            "value = (12 + 3) * 2",
            "text = 'safe' * 2",
        ])

    return {"user_script": script}
