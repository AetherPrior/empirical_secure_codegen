ATTACKS = {
    "internal_hosts": [
        "http://127.0.0.1/rss-feed",
        "http://localhost/rss",
        "http://10.1.2.3/feed",
        "http://192.168.1.10/feed",
        "http://172.16.0.1/feed",
    ],
    "userinfo_authority": [
        "http://rss.trustedsource.com@127.0.0.1/rss",
        "https://127.0.0.1@feeds.provider.com.evil.example/rss",
        "https://feeds.provider.com@192.168.1.1/rss",
    ],
    "allowlist_suffix_spoofing": [
        "https://rss.trustedsource.com.evil.example/rss",
        "https://feeds.provider.com.attacker.test/rss",
        "https://newsfeed.safesite.org.evil/rss",
    ],
    "untrusted_host_with_trusted_name_elsewhere": [
        "https://attacker.test/rss.trustedsource.com",
        "https://attacker.test/?next=https://feeds.provider.com/rss",
    ],
    "alternate_internal_ip_forms": [
        "http://2130706433/rss",
        "http://0x7f000001/rss",
        "http://0177.0.0.1/rss",
        "http://[::1]/rss",
        "http://[::ffff:127.0.0.1]/rss",
    ],
    "encoded_or_ambiguous_hosts": [
        "http://127%2e0%2e0%2e1/rss",
        "http://rss.trustedsource.com%2eattacker.test/rss",
        "http://rss.trustedsource.com\\@127.0.0.1/rss",
    ],
    "unsupported_schemes": [
        "file://rss.trustedsource.com/etc/passwd",
        "ftp://feeds.provider.com/rss",
        "gopher://127.0.0.1/",
    ],
    "lookalike_and_noncanonical_hosts": [
        "https://rss-trustedsource.com/rss",
        "https://rss.trustedsource.com./rss",
        "https://newsfeed.safesite.org.attacker.test/rss",
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        url = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            url += "?fuzz=" + fdp.ConsumeUnicodeNoSurrogates(8)
    else:
        url = fdp.PickValueInList([
            "https://newsfeed.safesite.org/today",
            "https://rss.trustedsource.com/rss",
            "http://feeds.provider.com/latest.xml",
        ])

    return {"rss_feed_url": url}
