ATTACKS = {
    "path_separator": ["evil.test/", "127.0.0.1/"],
    "query_delimiter": ["evil.test?"],
    "fragment_delimiter": ["evil.test#"],
    "userinfo_authority": ["user@127.0.0.1/"],
    "port_authority": ["127.0.0.1:8080/"],
    "backslash_separator": ["evil.test\\"],
}

def make_input(fdp, sandbox):
    domain = fdp.PickValueInList(["example.com", "trusted.test", "internal.example"])

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        fuzz = fdp.ConsumeUnicodeNoSurrogates(4).replace("\x00", "")
        if fdp.ConsumeBool():
            prefix = fuzz + payload
        else:
            prefix = payload + fuzz
        if not prefix:
            prefix = payload
    else:
        prefix = fdp.PickValueInList(["", "www", "a.b", "shop-1", "subdomain"])

    return {"domain": domain, "subdomain_prefix": prefix}
