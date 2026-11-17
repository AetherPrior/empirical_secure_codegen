ATTACKS = {
    "path_delimiter": [
        "127.0.0.1/",
        "169.254.169.254/",
        "evil.example/",
        "evil.example:443/",
    ],
    "query_delimiter": [
        "127.0.0.1?",
        "evil.example?",
    ],
    "fragment_delimiter": [
        "127.0.0.1#",
        "evil.example#",
    ],
    "userinfo_host_injection": [
        "attacker@127.0.0.1/",
        "attacker@169.254.169.254/",
    ],
    "backslash_delimiter": [
        "127.0.0.1\\",
        "evil.example\\",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        suffix = fdp.ConsumeUnicodeNoSurrogates(4)
        suffix = "".join(c for c in suffix if c.isascii() and (c.isalnum() or c in ".-"))
        subdomain_prefix = payload + suffix
    else:
        benign_values = ["", "subdomain", "a.b", "www", "service-1"]
        subdomain_prefix = fdp.PickValueInList(benign_values)

    return {
        "domain": "example.com",
        "subdomain_prefix": subdomain_prefix,
    }
