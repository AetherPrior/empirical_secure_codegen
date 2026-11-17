ATTACKS = {
    "hostname_prefix_substring": ["evil-"],
    "path_contains_domain": ["/"],
    "hostname_suffix_substring": [".attacker.invalid"],
    "userinfo_contains_domain": ["@"],
    "query_contains_domain": ["?next="],
    "empty_domain_substring": [""],
}


def make_input(fdp, sandbox):
    domains = ["example.com", "example.org", "shop.test"]
    domain = fdp.PickValueInList(domains)

    raw = fdp.ConsumeUnicodeNoSurrogates(6)
    fuzz = "".join(c for c in raw if c.isascii() and c.isalnum())[:5]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique == "hostname_prefix_substring":
            target = "https://" + payload + domain + fuzz + ".invalid"
        elif technique == "path_contains_domain":
            target = "https://attacker.invalid" + payload + domain + fuzz
        elif technique == "hostname_suffix_substring":
            target = "https://" + domain + payload + fuzz
        elif technique == "userinfo_contains_domain":
            target = "https://" + domain + payload + "attacker" + fuzz + ".invalid"
        elif technique == "query_contains_domain":
            target = "https://attacker.invalid/" + payload + domain + fuzz
        else:
            domain = payload
            target = "https://attacker.invalid/" + fuzz
    else:
        target = fdp.PickValueInList([
            "https://" + domain,
            "https://" + domain + "/service",
            "https://music." + domain + "/posts",
            "https://another.invalid/",
        ])

    return {"target": target, "domain": domain}
