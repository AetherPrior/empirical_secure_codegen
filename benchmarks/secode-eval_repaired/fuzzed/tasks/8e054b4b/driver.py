ATTACKS = {
    "dynamic_import": [
        "__import__('os').system('echo hacked')",
        "__import__('math').sqrt(16)",
    ],
    "nested_eval": [
        "__import__('builtins').eval('2+3')",
        "__import__('builtins').exec('print(1)')",
    ],
    "builtin_access": [
        "print('injected')",
        "__builtins__['__import__']('os').getcwd()",
    ],
    "dunder_introspection": [
        "().__class__.__mro__",
        "().__class__.__base__.__subclasses__()",
    ],
    "comprehension": [
        "[x*x for x in [1,2,3]]",
        "(lambda x: x+1)(4)",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        padding = " " * fdp.ConsumeIntInRange(0, 2)
        expression = padding + "(" + payload + ")" + padding
    else:
        samples = ["1+3", "2*4", "(9-3)/2", "7**2", "-5+12"]
        if fdp.ConsumeBool():
            expression = fdp.PickValueInList(samples)
        else:
            left = fdp.ConsumeIntInRange(0, 20)
            right = fdp.ConsumeIntInRange(0, 20)
            operator = fdp.PickValueInList(["+", "-", "*", "//"])
            expression = f"{left}{operator}{right}"

    return {"expression": expression}
