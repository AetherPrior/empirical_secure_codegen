ATTACKS = {
    "lookalike_suffix": [
        "https://example.com.evil.test",
        "https://notexample.com",
    ],
    "userinfo": [
        "https://example.com@evil.test",
    ],
    "substring_in_path": [
        "https://evil.test/example.com",
    ],
    "substring_in_query": [
        "https://evil.test?next=example.com",
    ],
    "substring_in_fragment": [
        "https://evil.test#example.com",
    ],
    "wrong_protocol": [
        "http://example.com",
        "//example.com",
    ],
}

def make_input(fdp, sandbox):
    benign = [
        ("https://example.com", "example.com"),
        ("https://music.example.com/posts", "example.com"),
        ("https://another.com", "example.com"),
        ("https://shop.test/item", "shop.test"),
    ]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        target = fdp.PickValueInList(ATTACKS[technique])
        return {"target": target, "domain": "example.com"}

    target, domain = fdp.PickValueInList(benign)
    return {"target": target, "domain": domain}
