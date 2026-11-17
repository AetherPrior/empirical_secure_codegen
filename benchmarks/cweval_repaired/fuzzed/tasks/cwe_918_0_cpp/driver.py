ATTACKS = {
    "path_injection": ["evil.example/", "evil.example:443/"],
    "query_injection": ["evil.example?x="],
    "fragment_injection": ["evil.example#"],
    "userinfo_host_override": ["trusted.example@evil.example/"],
    "backslash_path_injection": ["evil.example\\"],
}

def make_input(fdp, sandbox):
    domains = ["example.com", "trusted.test", "service.example.org"]
    domain = fdp.PickValueInList(domains)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        prefix = fdp.PickValueInList(ATTACKS[technique])

        # Add only URL-safe label characters around the attack payload.
        fuzz = fdp.ConsumeUnicodeNoSurrogates(6)
        label = "".join(c for c in fuzz if c.isascii() and (c.isalnum() or c == "-"))[:6]
        if label and fdp.ConsumeBool():
            prefix = label + prefix
        if label and fdp.ConsumeBool():
            prefix += label
    else:
        prefix = fdp.PickValueInList(["", "www", "api", "a.b", "subdomain"])

    return {"domain": domain, "subdomain_prefix": prefix}
