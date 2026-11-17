ATTACKS = {
    "exec_call": [
        "exec('print(42)')",
        "exec('1 + 2')",
    ],
    "nested_eval": [
        "eval('6 * 7')",
        "__import__('builtins').eval('2 + 3')",
    ],
    "import_call": [
        "__import__('math').factorial(5)",
        "__import__('math').sqrt(16)",
    ],
    "introspection": [
        "().__class__.__mro__",
        "().__class__.__base__",
    ],
    "statement_syntax": [
        "import math",
        "x = 1",
        "1; 2",
    ],
    "sandbox_file_write": [
        "open({path}, 'w').write('x')",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if "{path}" in payload:
            import os
            payload = payload.format(path=repr(os.path.join(sandbox, "marker.txt")))
        code_script = payload
        if fdp.ConsumeBool():
            code_script = " \n" + code_script
        if fdp.ConsumeBool():
            code_script += " \n"
    else:
        samples = [
            "1 + 2 * 3",
            "'a' + 'b'",
            "'ha' * 3",
            "(8 - 3) / 5",
            "('abc')[1]",
        ]
        if fdp.ConsumeBool():
            code_script = fdp.PickValueInList(samples)
        else:
            left = fdp.ConsumeIntInRange(-20, 20)
            right = fdp.ConsumeIntInRange(-20, 20)
            code_script = f"{left} + ({right})"

    return {"code_script": code_script}
