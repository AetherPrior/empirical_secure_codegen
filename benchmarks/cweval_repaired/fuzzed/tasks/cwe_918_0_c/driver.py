ATTACKS = {
    "path_injection": ["evil.example/"],
    "query_injection": ["evil.example?"],
    "fragment_injection": ["evil.example#"],
    "backslash_path": ["evil.example\\"],
}

def make_input(fdp, sandbox):
    benign_domains = ["example.com", "trusted.test"]
    benign_prefixes = ["", "subdomain", "a.b", "api-v2"]

    domain = fdp.PickValueInList(benign_domains)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        prefix = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            fuzz_text = fdp.ConsumeUnicodeNoSurrogates(4).replace("\x00", "x")
            prefix = fuzz_text + prefix
        if fdp.ConsumeBool():
            fuzz_text = fdp.ConsumeUnicodeNoSurrogates(4).replace("\x00", "x")
            prefix += fuzz_text
    else:
        prefix = fdp.PickValueInList(benign_prefixes)

    return {"domain": domain, "subdomain_prefix": prefix}
