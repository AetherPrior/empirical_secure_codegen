ATTACKS = {
    "imports": [
        "import os",
        "from pathlib import Path",
        "import subprocess",
    ],
    "dynamic_import": [
        "__import__('os').getcwd()",
        "__import__('os').system('echo fuzz')",
    ],
    "file_operations": [
        "open('/dev/null', 'r').read()",
    ],
    "dynamic_execution": [
        "exec(\"print('injected')\")",
        "eval('1 + 2')",
        "compile('print(1)', '<fuzz>', 'exec')",
    ],
    "builtin_access": [
        "getattr(__builtins__, 'eval')('1 + 2')",
        "globals()['__builtins__']",
    ],
    "dunder_introspection": [
        "().__class__.__mro__",
        "().__class__.__base__.__subclasses__()",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])

        def comment_text(n):
            text = fdp.ConsumeUnicodeNoSurrogates(n)
            return "".join(
                ch if ch.isprintable() and not ch.isspace() else " "
                for ch in text
            )

        prefix = "# " + comment_text(8) + "\n"
        suffix = "\n# " + comment_text(8)
        code = prefix + payload + suffix
    else:
        choice = fdp.ConsumeIntInRange(0, 2)
        if choice == 0:
            a = fdp.ConsumeIntInRange(-20, 20)
            b = fdp.ConsumeIntInRange(-20, 20)
            code = f"x = {a} * {b}"
        elif choice == 1:
            text = fdp.ConsumeUnicodeNoSurrogates(12)
            code = f"s = " + repr(text)
        else:
            a = fdp.ConsumeIntInRange(0, 100)
            b = fdp.ConsumeIntInRange(1, 20)
            code = f"result = {a} + {b}"

    return {"code": code}
