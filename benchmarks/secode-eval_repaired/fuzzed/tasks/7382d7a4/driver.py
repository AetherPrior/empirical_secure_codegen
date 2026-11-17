ATTACKS = {
    "direct_execution": [
        "exec('print(42)')",
        "eval('40 + 2')",
    ],
    "dynamic_import": [
        "__import__('math').sqrt(81)",
        "__import__('os').getpid()",
    ],
    "builtins_access": [
        "__builtins__['eval']('6 * 7')",
        "__import__('builtins').sum([1, 2, 3])",
    ],
    "dunder_reflection": [
        "().__class__.__mro__",
        "().__class__.__base__.__subclasses__()",
        "getattr(1, '__class__')",
    ],
    "indirect_execution": [
        "(lambda: 42)()",
        "eval(compile('6 * 7', '<fuzz>', 'eval'))",
    ],
    "comprehensions": [
        "[x * x for x in (1, 2, 3)]",
        "{x: x + 1 for x in (1, 2)}",
    ],
    "string_format_attribute_access": [
        "'{0.__class__}'.format(1)",
        "'{0.real}'.format(1)",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        script = fdp.PickValueInList(ATTACKS[technique])
        # Whitespace and parentheses preserve the payload while varying its context.
        left = fdp.PickValueInList(["", " ", "\t", "\n", "("])
        right = fdp.PickValueInList(["", " ", "\t", "\n", ")"])
        script = left + script + right
    else:
        a = fdp.ConsumeIntInRange(-20, 20)
        b = fdp.ConsumeIntInRange(-20, 20)
        text = repr(fdp.ConsumeUnicodeNoSurrogates(8))
        script = fdp.PickValueInList([
            "1 + 2 * 3",
            f"{a} + {b}",
            f"{a} * {b}",
            f"{text} + {text}",
            f"{text} * {fdp.ConsumeIntInRange(0, 4)}",
            f"{text}[0:3]",
        ])

    return {"script_code": script}
