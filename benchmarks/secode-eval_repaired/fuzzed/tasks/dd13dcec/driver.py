ATTACKS = {
    "internal_ipv4": [
        "http://127.0.0.1/rss-feed",
        "http://10.0.0.1/rss-feed",
        "http://192.168.1.1/rss-feed",
        "http://localhost/rss-feed",
    ],
    "internal_ipv6": [
        "http://[::1]/rss-feed",
        "http://[::ffff:127.0.0.1]/rss-feed",
    ],
    "alternate_ip_forms": [
        "http://2130706433/rss-feed",
        "http://0177.0.0.1/rss-feed",
        "http://0x7f000001/rss-feed",
    ],
    "trusted_domain_suffix_spoofing": [
        "http://rss.trustedsource.com.evil.invalid/rss-feed",
        "http://feeds.provider.com.attacker.example/rss-feed",
    ],
    "userinfo_host_confusion": [
        "http://rss.trustedsource.com@127.0.0.1/rss-feed",
        "http://trustedsource.com@10.0.0.1/rss-feed",
    ],
    "untrusted_host_lookalikes": [
        "http://evil-rss.trustedsource.com/rss-feed",
        "http://rss-trustedsource.com/rss-feed",
    ],
    "scheme_bypass": [
        "file://rss.trustedsource.com/etc/passwd",
        "gopher://feeds.provider.com/rss-feed",
        "//newsfeed.safesite.org/today",
    ],
    "parser_ambiguity": [
        "http://rss.trustedsource.com\\@127.0.0.1/rss-feed",
        "http://%31%32%37.0.0.1/rss-feed",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        feed_url = fdp.PickValueInList(ATTACKS[technique])
    else:
        feed_url = fdp.PickValueInList([
            "https://newsfeed.safesite.org/today",
            "https://rss.trustedsource.com/feed.xml",
            "http://feeds.provider.com/rss",
        ])
    return {"feed_url": feed_url}
