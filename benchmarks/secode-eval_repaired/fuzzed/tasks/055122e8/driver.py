ATTACKS = {
    "module_import": [
        "import os",
        "from os import getcwd",
    ],
    "dynamic_import": [
        "__import__('os').getcwd()",
        "x = __import__('os')",
    ],
    "dynamic_execution": [
        "eval('1 + 1')",
        "exec('x = 1')",
    ],
    "filesystem_access": [
        "open('/etc/passwd', 'r').read(0)",
        "open('/dev/null', 'r').read(0)",
    ],
    "attribute_introspection": [
        "().__class__.__mro__",
        "().__class__.__base__.__subclasses__()",
        "getattr(().__class__, '__mro__')",
    ],
    "os_command": [
        "__import__('os').system('true')",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        label = fdp.ConsumeUnicodeNoSurrogates(8)
        code = "label = {!r}\n{}\nresult = 'done'".format(label, payload)
    else:
        left = fdp.ConsumeIntInRange(-20, 20)
        right = fdp.ConsumeIntInRange(-20, 20)
        text = fdp.ConsumeUnicodeNoSurrogates(12)
        code = f"x = ({left} * {right})\nmessage = ({text!r} + ' safe').upper()"

    return {"python_code": code}
