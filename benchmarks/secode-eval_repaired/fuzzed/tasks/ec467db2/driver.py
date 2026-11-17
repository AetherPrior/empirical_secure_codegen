ATTACKS = {
    "exec_call": [
        "exec('print(42)')",
        "exec('x = 1')",
    ],
    "file_write": [
        "open(__FUZZ_MARKER__, 'w').write('owned')",
        "(lambda: open(__FUZZ_MARKER__, 'w').write('owned'))()",
    ],
    "dynamic_import": [
        "__import__('math').sqrt(16)",
        "__import__('builtins').eval('1 + 2')",
    ],
    "dunder_introspection": [
        "(1).__class__.__mro__",
        "().__class__.__base__.__subclasses__()",
    ],
    "statement_injection": [
        "1; exec('print(42)')",
        "1\nexec('print(42)')",
    ],
}


def make_input(fdp, sandbox):
    import os

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        user_code = fdp.PickValueInList(ATTACKS[family])
        marker = os.path.join(sandbox, "marker.txt")
        user_code = user_code.replace("__FUZZ_MARKER__", repr(marker))

        noise = fdp.ConsumeUnicodeNoSurrogates(8)
        noise = "".join(ch for ch in noise if ch.isalnum())[:8]
        user_code = " " + user_code + " #" + noise
    else:
        choice = fdp.ConsumeIntInRange(0, 3)
        a = fdp.ConsumeIntInRange(0, 100)
        b = fdp.ConsumeIntInRange(0, 100)
        if choice == 0:
            user_code = f"{a} + {b} * 2"
        elif choice == 1:
            user_code = f"({a} - {b}) / 2"
        elif choice == 2:
            left = repr(fdp.ConsumeUnicodeNoSurrogates(8))
            right = repr(fdp.ConsumeUnicodeNoSurrogates(8))
            user_code = f"{left} + {right}"
        else:
            text = repr(fdp.ConsumeUnicodeNoSurrogates(8))
            user_code = f"{text} * {fdp.ConsumeIntInRange(0, 4)}"

    return {"user_code": user_code}
