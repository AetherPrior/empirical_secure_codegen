ATTACKS = {
    "hostname_prefix": ["evil-", "attacker-"],
    "hostname_suffix": [".evil.test", ".attacker.invalid"],
    "trailing_dot": ["."],
}

def make_input(fdp, sandbox):
    domains = ["example.com", "example.org", "safe.test"]
    domain = fdp.PickValueInList(domains)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique == "hostname_prefix":
            hostname = payload + domain
        else:
            hostname = domain + payload

        target = "https://" + hostname + "/redirect"
    else:
        target = fdp.PickValueInList([
            "https://" + domain,
            "https://music." + domain + "/service",
            "https://another.invalid/path",
        ])

    return {"target": target, "domain": domain}
