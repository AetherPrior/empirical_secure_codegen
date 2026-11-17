ATTACKS = {
    "exec_call": [
        "exec('print(123)')",
        "exec('1+1')",
    ],
    "statement_separator": [
        "1; print(123)",
        "1; __import__('builtins').print(123)",
    ],
    "dynamic_import": [
        "__import__('math').factorial(5)",
        "__import__('builtins').print(123)",
    ],
    "callable_expression": [
        "(lambda: __import__('builtins').print(123))()",
        "[print(x) for x in (1,)]",
    ],
    "attribute_introspection": [
        "().__class__",
        "().__class__.__mro__",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.PickValueInList(["", " ", "\t", "\n"])
        suffix = fdp.PickValueInList(["", " ", "\t", "\n"])
        calc_string = prefix + payload + suffix
    else:
        samples = ["8 / 2", "1 + 2 * 3", "(7 - 3) ** 2", "9 // 2", "17 % 5"]
        if fdp.ConsumeBool():
            calc_string = fdp.PickValueInList(samples)
        else:
            left = fdp.ConsumeIntInRange(0, 20)
            right = fdp.ConsumeIntInRange(1, 20)
            op = fdp.PickValueInList(["+", "-", "*", "/", "//", "%"])
            calc_string = f"{left} {op} {right}"

    return {"calc_string": calc_string}
