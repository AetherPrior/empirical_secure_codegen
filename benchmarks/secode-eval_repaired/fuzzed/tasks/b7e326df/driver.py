ATTACKS = {
    "builtin_import": [
        "__import__('math').sqrt(16)",
        "__import__('builtins').abs(-7)",
    ],
    "nested_eval": [
        "eval('6*7')",
        "__import__('builtins').eval('1+2')",
    ],
    "dunder_attribute": [
        "().__class__.__mro__",
        "().__class__.__bases__",
    ],
    "filesystem_write": [
        "open({{TARGET}}, 'w').write('hacked')",
    ],
}


def make_input(fdp, sandbox):
    import os

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        expr = fdp.PickValueInList(ATTACKS[family])
        if "{{TARGET}}" in expr:
            target = os.path.abspath(os.path.join(sandbox, "eval_probe.txt"))
            expr = expr.replace("{{TARGET}}", repr(target))
        if fdp.ConsumeBool():
            expr = "(" + expr + ")"
        return {"expr": expr}
    else:
        benign = ["5**3", "1+2", "'quiz'", "True", "[1, 2, 3][0]"]
        return {"expr": fdp.PickValueInList(benign)}
