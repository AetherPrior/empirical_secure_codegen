ATTACKS = {
    "path_authority_termination": ["attacker.invalid/"],
    "query_authority_termination": ["attacker.invalid?x="],
    "fragment_authority_termination": ["attacker.invalid#"],
    "userinfo_host_injection": ["trusted@attacker.invalid/"],
    "port_injection": ["attacker.invalid:443/"],
}


def make_input(fdp, sandbox):
    domains = ["example.com", "trusted.test", "service.internal"]
    domain = fdp.PickValueInList(domains)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        # Keep fuzz text to URL-safe label characters so the payload's URL
        # delimiter remains effective.
        fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
        fuzz = "".join(
            ch for ch in fuzz
            if ch.isascii() and (ch.isalnum() or ch == "-")
        )
        prefix = fuzz[:4] + payload + fuzz[4:]
    else:
        prefix = fdp.PickValueInList([
            "",
            "shop",
            "a.b",
            "sub-domain",
            "api.v2",
        ])

    return {"domain": domain, "subdomain_prefix": prefix}
