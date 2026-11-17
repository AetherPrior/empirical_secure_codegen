ATTACKS = {
    "names": [
        "a",
        "__import__",
        "open",
    ],
    "imports_and_calls": [
        "__import__('os').getcwd()",
        "__import__('math').sqrt(16)",
        "eval('1+2')",
        "exec('x=1')",
    ],
    "sandbox_file_write": [
        "__import__('pathlib').Path({SANDBOX} + '/owned.txt').write_text('pwned')",
    ],
    "attribute_introspection": [
        "().__class__.__mro__",
        "().__class__.__base__",
        "True.__class__",
    ],
    "non_math_expressions": [
        "[x for x in (1,)]",
        "(lambda: 7)()",
        "'text'",
        "1 == 1",
    ],
    "statement_syntax": [
        "1; __import__('os').getcwd()",
        "__import__('os').getcwd(); 1",
    ],
}


def make_input(fdp, sandbox):
    benign = [
        "20 + 3 * 2",
        "(8 - 3) * 4",
        "18 / 3",
        "7 + (6 * 2)",
        "42 - 19",
        "3 / a",
    ]

    if not fdp.ConsumeBool():
        return {"exp_str": fdp.PickValueInList(benign)}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])
    payload = payload.replace("{SANDBOX}", repr(sandbox))

    # Whitespace preserves the payload while varying its surrounding text.
    prefix = fdp.PickValueInList(["", " ", "\n", "\t"])
    suffix = fdp.PickValueInList(["", " ", "\n", "\t"])
    if fdp.ConsumeBool():
        payload = "(" + payload + ")"

    return {"exp_str": prefix + payload + suffix}
