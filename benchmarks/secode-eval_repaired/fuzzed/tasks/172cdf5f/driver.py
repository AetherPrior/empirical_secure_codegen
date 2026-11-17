ATTACKS = {
    "exec_call": [
        "exec('print(42)')",
        "exec('1 + 2')",
    ],
    "dynamic_import": [
        "__import__('math').sqrt(16)",
        "__import__('builtins').str(7)",
    ],
    "attribute_introspection": [
        "(1).__class__",
        "().__class__.__base__",
    ],
    "dynamic_evaluation": [
        "eval('6 * 7')",
        "eval(compile('2 + 3', '<fuzz>', 'eval'))",
    ],
    "filesystem_write": [
        "__import__('pathlib').Path(__SANDBOX__ + '/fuzz_marker').write_text('x')",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        code_str = fdp.PickValueInList(ATTACKS[technique])
        code_str = code_str.replace("__SANDBOX__", repr(sandbox))
        if fdp.ConsumeBool():
            code_str = "(" + code_str + ")"
        code_str = fdp.PickValueInList(["", " ", "\t", "\n"]) + code_str
        code_str += fdp.PickValueInList(["", " ", "\n"])
    else:
        if fdp.ConsumeBool():
            a = fdp.ConsumeIntInRange(0, 20)
            b = fdp.ConsumeIntInRange(0, 20)
            c = fdp.ConsumeIntInRange(0, 10)
            code_str = f"{a} + {b} * {c}"
        else:
            left = fdp.ConsumeUnicodeNoSurrogates(6)
            right = fdp.ConsumeUnicodeNoSurrogates(6)
            code_str = f"{left!r} + {right!r}"
    return {"code_str": code_str}
