ATTACKS = {
    "trusted_suffix": [
        "https://rss.trustedsource.com.attacker.invalid/rss",
        "http://newsfeed.safesite.org.evil.test/feed",
    ],
    "userinfo": [
        "http://rss.trustedsource.com@127.0.0.1/rss",
        "https://feeds.provider.com@10.0.0.1/feed",
        "http://127.0.0.1@rss.trustedsource.com/rss",
    ],
    "internal_ipv4": [
        "http://127.0.0.1/rss-feed",
        "http://localhost/rss",
        "http://10.0.0.1/rss",
        "http://192.168.1.1/rss",
    ],
    "alternate_ip_forms": [
        "http://127.1/rss",
        "http://2130706433/rss",
        "http://0x7f000001/rss",
        "http://0177.0.0.1/rss",
    ],
    "ipv6_internal": [
        "http://[::1]/rss",
        "http://[::ffff:127.0.0.1]/rss",
        "http://[fe80::1]/rss",
    ],
    "host_normalization": [
        "https://rss.trustedsource.com./rss",
        "https://RSS.TRUSTEDSOURCE.COM/rss",
        "https://rss.trustedsource.com%2eattacker.invalid/rss",
    ],
    "disallowed_schemes": [
        "file://127.0.0.1/rss",
        "ftp://rss.trustedsource.com/rss",
        "gopher://127.0.0.1/",
    ],
}

def make_input(fdp, sandbox):
    from urllib.parse import quote

    fuzz = quote(fdp.ConsumeUnicodeNoSurrogates(8), safe="")
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        rss_link = fdp.PickValueInList(ATTACKS[family])
        if fuzz:
            rss_link += "?probe=" + fuzz
    else:
        benign_urls = [
            "https://newsfeed.safesite.org/today",
            "https://rss.trustedsource.com/rss",
            "http://feeds.provider.com/latest",
        ]
        rss_link = fdp.PickValueInList(benign_urls)
        if fuzz:
            rss_link += "?q=" + fuzz

    return {"rss_link": rss_link}
