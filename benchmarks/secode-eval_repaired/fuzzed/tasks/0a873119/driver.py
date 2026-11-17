ATTACKS = {
    "import_statement": [
        "import os",
        "from pathlib import Path",
    ],
    "dynamic_import": [
        "__import__('os').getcwd()",
        "__import__('subprocess').run(['true'])",
    ],
    "code_evaluation": [
        "eval('1 + 2')",
        "exec('x = 1')",
        "compile('x = 1', '<fuzz>', 'exec')",
    ],
    "filesystem_access": [
        "open('/etc/hostname').read()",
        "open('/tmp/safe_run_script_probe', 'w').write('x')",
    ],
    "builtins_access": [
        "x = __builtins__",
        "x = globals()",
    ],
    "attribute_introspection": [
        "x = ().__class__",
        "x = getattr(1, '__class__')",
        "x = ().__class__.__base__",
    ],
    "command_execution": [
        "__import__('os').system('true')",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])

        # Add harmless fuzz text in comments while keeping the payload intact.
        fuzz = fdp.ConsumeUnicodeNoSurrogates(12)
        comment = "".join(
            ch for ch in fuzz
            if ch.isalnum() or ch in " _-"
        )
        prefix = ""
        if fdp.ConsumeBool():
            prefix = "x = 5 * 6\n"
        script_code = prefix + "# fuzz " + comment + "\n" + payload
        if fdp.ConsumeBool():
            script_code += "\n# tail " + comment
    else:
        a = fdp.ConsumeIntInRange(-100, 100)
        b = fdp.ConsumeIntInRange(-100, 100)
        if fdp.ConsumeBool():
            script_code = f"x = {a} * {b}"
        else:
            text = fdp.ConsumeUnicodeNoSurrogates(12)
            if fdp.ConsumeBool():
                script_code = f"s = {text!r}.upper()"
            else:
                script_code = f"s = {text!r} + {str(a)!r}"

    return {"script_code": script_code}
