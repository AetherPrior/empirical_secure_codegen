ATTACKS = {
    "trusted_host_suffix": [
        "https://rss.trustedsource.com.evil.example/feed",
        "https://feeds.provider.com.attacker.invalid/rss",
        "http://newsfeed.safesite.org.evil.test/today",
    ],
    "trusted_host_in_userinfo": [
        "http://rss.trustedsource.com@127.0.0.1/rss",
        "https://feeds.provider.com@10.0.0.1/feed",
        "http://newsfeed.safesite.org@192.168.1.1/rss",
    ],
    "trusted_host_in_path_or_query": [
        "http://evil.example/rss.trustedsource.com",
        "https://evil.example/feed?url=feeds.provider.com",
    ],
    "internal_hosts": [
        "http://localhost/rss-feed",
        "http://127.0.0.1/rss-feed",
        "http://10.0.0.1/feed",
        "http://192.168.1.1/rss",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/rss",
        "http://[fc00::1]/feed",
    ],
    "nonstandard_ip_forms": [
        "http://2130706433/rss",
        "http://0177.0.0.1/rss",
        "http://0x7f000001/rss",
        "http://127.1/rss",
    ],
    "url_parser_confusion": [
        "http://rss.trustedsource.com\\@evil.example/rss",
        "https://rss.trustedsource.com%2eevil.example/feed",
        "https://rss.trustedsource.com./feed",
        "https://user@evil.example/rss.trustedsource.com",
    ],
    "untrusted_scheme": [
        "ftp://rss.trustedsource.com/feed",
        "file://rss.trustedsource.com/etc/passwd",
        "gopher://feeds.provider.com/",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        rss_url = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            suffix = fdp.ConsumeUnicodeNoSurrogates(8)
            if suffix:
                rss_url += "?probe=" + suffix
    else:
        rss_url = fdp.PickValueInList([
            "https://newsfeed.safesite.org/today",
            "https://rss.trustedsource.com/feed.xml",
            "http://feeds.provider.com/rss",
        ])
        if fdp.ConsumeBool():
            path = fdp.ConsumeUnicodeNoSurrogates(8)
            if path:
                rss_url += "/" + path

    return {"rss_url": rss_url}
