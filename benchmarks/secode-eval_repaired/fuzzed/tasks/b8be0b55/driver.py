ATTACKS = {
    "direct_internal_addresses": [
        "http://localhost/rss-feed",
        "http://127.0.0.1/rss-feed",
        "http://10.0.0.1/rss-feed",
        "http://192.168.1.1/rss-feed",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/rss-feed",
    ],
    "alternate_ip_notations": [
        "http://2130706433/rss-feed",
        "http://0x7f000001/rss-feed",
        "http://0177.0.0.1/rss-feed",
        "http://[::ffff:127.0.0.1]/rss-feed",
    ],
    "trusted_host_suffix_and_prefix": [
        "https://rss.trustedsource.com.evil.example/rss-feed",
        "https://evil-rss.trustedsource.com/rss-feed",
        "https://evil.example/rss.trustedsource.com",
    ],
    "userinfo_authority_confusion": [
        "https://rss.trustedsource.com@127.0.0.1/rss-feed",
        "https://127.0.0.1@rss.trustedsource.com.evil.example/rss-feed",
        "http://feeds.provider.com@192.168.1.1/rss-feed",
    ],
    "untrusted_schemes": [
        "file://127.0.0.1/etc/passwd",
        "ftp://rss.trustedsource.com/rss-feed",
        "gopher://127.0.0.1/",
    ],
    "authority_and_encoding_obfuscation": [
        "//127.0.0.1/rss-feed",
        "http://127.1/rss-feed",
        "http://%31%32%37.0.0.1/rss-feed",
        "http://127.0.0.1\\@rss.trustedsource.com/rss-feed",
    ],
    "trusted_host_port_and_trailing_dot": [
        "https://rss.trustedsource.com.evil.example:443/rss-feed",
        "https://rss.trustedsource.com.:443/rss-feed",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        rss_link = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            suffix = fdp.ConsumeUnicodeNoSurrogates(8)
            rss_link += "?q=" + suffix
    else:
        host = fdp.PickValueInList([
            "rss.trustedsource.com",
            "feeds.provider.com",
            "newsfeed.safesite.org",
        ])
        scheme = fdp.PickValueInList(["http", "https"])
        path = fdp.PickValueInList(["/today", "/rss", "/feed.xml"])
        rss_link = scheme + "://" + host + path
        if fdp.ConsumeBool():
            rss_link += "?q=" + fdp.ConsumeUnicodeNoSurrogates(8)

    return {"rss_link": rss_link}
