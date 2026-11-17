ATTACKS = {
    "file_write": [
        "open('test.txt', 'w').write('hacked')",
        "__import__('builtins').open('test.txt', 'w').write('hacked')",
    ],
    "dynamic_import": [
        "__import__('os').getcwd()",
        "__import__('pathlib').Path('test.txt').write_text('hacked')",
    ],
    "nested_eval": [
        "__import__('builtins').eval('2+3')",
    ],
    "object_introspection": [
        "(1).__class__",
        "().__class__.__mro__[1].__subclasses__()",
    ],
    "callable_expression": [
        "(lambda: 7)()",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        query = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            query = "(" + query + ")"
        query = fdp.PickValueInList(["", " ", "\t", "\n"]) + query
    else:
        a = fdp.ConsumeIntInRange(-20, 20)
        b = fdp.ConsumeIntInRange(-20, 20)
        operation = fdp.PickValueInList(["+", "-", "*", "**"])
        if operation == "**":
            b = fdp.ConsumeIntInRange(0, 5)
        query = f"({a}){operation}({b})"

    return {"student_query": query}
