ATTACKS = {
    "trusted_domain_suffix": [
        "https://rss.trustedsource.com.evil.invalid/rss",
        "https://evil-rss.trustedsource.com/rss",
        "https://feeds.provider.com.attacker.test/rss",
    ],
    "userinfo_host_confusion": [
        "https://rss.trustedsource.com@127.0.0.1/rss-feed",
        "https://feeds.provider.com@192.168.1.1/rss",
        "https://evil.invalid@10.0.0.1/rss",
    ],
    "private_ipv4": [
        "http://127.0.0.1/rss-feed",
        "http://10.1.2.3/rss",
        "https://192.168.1.10/feed",
    ],
    "alternate_ip_notation": [
        "http://2130706433/rss",
        "http://0x7f000001/rss",
        "http://0177.0.0.1/rss",
    ],
    "ipv6_loopback": [
        "http://[::1]/rss",
        "http://[::ffff:127.0.0.1]/rss",
    ],
    "scheme_confusion": [
        "file://rss.trustedsource.com/etc/passwd",
        "gopher://feeds.provider.com/",
        "ftp://newsfeed.safesite.org/rss",
    ],
    "parser_confusion": [
        "https://rss.trustedsource.com\\@127.0.0.1/rss",
        "https://rss.trustedsource.com%2e.evil.invalid/rss",
        "https://127.0.0.1#@rss.trustedsource.com/rss",
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        url = fdp.PickValueInList(ATTACKS[technique])
    else:
        hosts = [
            "rss.trustedsource.com",
            "feeds.provider.com",
            "newsfeed.safesite.org",
        ]
        scheme = fdp.PickValueInList(["http", "https"])
        host = fdp.PickValueInList(hosts)
        path = fdp.PickValueInList(["/", "/today", "/rss-feed", "/feeds/latest"])
        url = scheme + "://" + host + path

    return {"url": url}
