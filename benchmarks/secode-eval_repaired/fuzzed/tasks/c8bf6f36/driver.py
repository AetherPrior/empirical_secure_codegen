ATTACKS = {
    "userinfo_host_confusion": [
        "http://rss.trustedsource.com@127.0.0.1/rss",
        "https://feeds.provider.com@10.0.0.1/feed",
        "http://evil.example@newsfeed.safesite.org/rss",
    ],
    "trusted_name_in_untrusted_host": [
        "http://rss.trustedsource.com.evil.example/rss",
        "https://feeds.provider.com.attacker.test/feed",
        "http://evil.example/rss.trustedsource.com",
        "https://evil.example/?url=feeds.provider.com",
    ],
    "untrusted_subdomain": [
        "http://x.rss.trustedsource.com/rss",
        "https://evil.feeds.provider.com/feed",
    ],
    "internal_ipv4": [
        "http://127.0.0.1/rss-feed",
        "http://127.0.0.9/rss",
        "http://10.0.0.1/feed",
        "http://192.168.1.1/rss",
        "http://localhost/rss",
    ],
    "alternate_ip_notations": [
        "http://2130706433/rss",
        "http://0177.0.0.1/rss",
        "http://0x7f000001/rss",
        "http://127.1/rss",
        "http://%31%32%37.0.0.1/rss",
    ],
    "ipv6_internal": [
        "http://[::1]/rss",
        "http://[::ffff:127.0.0.1]/rss",
        "http://[fc00::1]/feed",
    ],
    "scheme_bypass": [
        "ftp://rss.trustedsource.com/feed",
        "file://rss.trustedsource.com/etc/passwd",
        "gopher://127.0.0.1/",
    ],
    "authority_and_parser_confusion": [
        "http://rss.trustedsource.com\\@127.0.0.1/rss",
        "http://127.0.0.1#@rss.trustedsource.com/rss",
        "http://127.0.0.1.:80/rss",
        "http://10.999.1.1/rss",
    ],
    "trusted_host_normalization": [
        "http://rss.trustedsource.com./rss",
        "https://RSS.TRUSTEDSOURCE.COM/feed",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        rss_link = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            suffix = fdp.ConsumeUnicodeNoSurrogates(8)
            rss_link += "?x=" + suffix
    else:
        rss_link = fdp.PickValueInList([
            "https://newsfeed.safesite.org/today",
            "https://rss.trustedsource.com/feed.xml",
            "http://feeds.provider.com/rss",
        ])
    return {"rss_link": rss_link}
