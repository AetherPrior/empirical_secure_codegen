ATTACKS = {
    "trusted_host_suffix": [
        "https://rss.trustedsource.com.evil.example/feed",
        "https://feeds.provider.com.attacker.invalid/rss",
        "https://newsfeed.safesite.org.evil.test/today",
    ],
    "trusted_name_in_userinfo": [
        "https://rss.trustedsource.com@evil.example/feed",
        "https://feeds.provider.com@127.0.0.1/rss",
    ],
    "trusted_name_in_path_or_query": [
        "https://evil.example/rss.trustedsource.com/feed",
        "https://evil.example/feed?url=feeds.provider.com",
    ],
    "internal_ipv4": [
        "http://127.0.0.1/rss-feed",
        "http://10.0.0.1/rss",
        "http://192.168.1.1/feed",
    ],
    "alternate_loopback_or_private_ip": [
        "http://2130706433/rss",
        "http://0x7f000001/feed",
        "http://0177.0.0.1/rss",
        "http://[::1]/feed",
        "http://[fc00::1]/feed",
    ],
    "localhost_variants": [
        "http://localhost/rss",
        "http://localhost./feed",
        "http://127.0.0.1.example.invalid/rss",
    ],
    "unsupported_scheme": [
        "file://rss.trustedsource.com/etc/passwd",
        "ftp://feeds.provider.com/rss",
        "gopher://127.0.0.1/",
    ],
    "authority_and_parser_confusion": [
        "https://rss.trustedsource.com\\@evil.example/feed",
        "https://evil.example\\\\rss.trustedsource.com/feed",
        "//rss.trustedsource.com.evil.example/feed",
    ],
    "untrusted_host": [
        "https://evil.example/rss",
        "http://attacker.invalid/feed",
    ],
}


def make_input(fdp, sandbox):
    benign = [
        "https://newsfeed.safesite.org/today",
        "https://rss.trustedsource.com/rss.xml",
        "http://feeds.provider.com/latest",
    ]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        address = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            fragment = fdp.ConsumeUnicodeNoSurrogates(6)
            address += "#" + fragment
    else:
        address = fdp.PickValueInList(benign)
        if fdp.ConsumeBool():
            query = fdp.ConsumeUnicodeNoSurrogates(6)
            address += "?q=" + query

    return {"rss_address": address}
