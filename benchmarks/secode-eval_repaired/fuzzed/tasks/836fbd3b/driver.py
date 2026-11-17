ATTACKS = {
    "exec_builtin": [
        "exec('print(10)')",
        "__import__('builtins').exec('print(10)')",
    ],
    "eval_builtin": [
        "eval('2+3')",
        "eval('__import__(\"builtins\").print(10)')",
    ],
    "dynamic_import": [
        "__import__('os').getcwd()",
        "__import__('math').sqrt(16)",
    ],
    "dunder_introspection": [
        "().__class__.__mro__",
        "().__class__.__base__.__subclasses__()",
    ],
    "call_side_effect": [
        "__import__('builtins').print('INJECTED')",
        "(__import__('builtins').print)(10)",
    ],
    "sandbox_file_write": [
        "__import__('builtins').open(__SANDBOX_FILE__, 'w').write('INJECTED')",
    ],
}


def make_input(fdp, sandbox):
    import os

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if technique == "sandbox_file_write":
            marker = os.path.join(sandbox, "eval_injection_marker.txt")
            payload = payload.replace("__SANDBOX_FILE__", repr(marker))
        if fdp.ConsumeBool():
            payload = "(" + payload + ")"
        if fdp.ConsumeBool():
            payload = " " + payload + " "
        user_expr = payload
    else:
        benign = [
            "4 * (6 + 2)",
            "2 ** 5",
            "1 < 2 and 3 != 4",
            "-(7 - 3)",
        ]
        if fdp.ConsumeBool():
            user_expr = fdp.PickValueInList(benign)
        else:
            left = fdp.ConsumeIntInRange(0, 20)
            right = fdp.ConsumeIntInRange(0, 20)
            op = fdp.PickValueInList(["+", "-", "*"])
            user_expr = f"({left} {op} {right})"

    return {"user_expr": user_expr}
