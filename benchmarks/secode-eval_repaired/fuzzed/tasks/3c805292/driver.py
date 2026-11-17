ATTACKS = {
    "trusted_host_suffix": [
        "http://rss.trustedsource.com.evil.test/rss",
        "https://feeds.provider.com.attacker.invalid/feed",
    ],
    "trusted_host_prefix": [
        "http://evil-rss.trustedsource.com/rss",
        "https://notfeeds.provider.com/feed",
    ],
    "userinfo_confusion": [
        "http://rss.trustedsource.com@evil.test/rss",
        "https://feeds.provider.com@127.0.0.1/feed",
    ],
    "trusted_host_as_username": [
        "http://evil.test@rss.trustedsource.com/rss",
    ],
    "internal_ipv4": [
        "http://127.0.0.1/rss-feed",
        "http://10.0.0.1/feed",
        "http://192.168.1.1/feed",
        "http://169.254.169.254/latest/meta-data/",
        "http://172.16.0.1/feed",
    ],
    "alternate_ip_notation": [
        "http://127.1/rss",
        "http://2130706433/rss",
        "http://0x7f000001/rss",
        "http://0177.0.0.1/rss",
    ],
    "localhost_variants": [
        "http://localhost/rss",
        "http://localhost.localdomain/rss",
        "http://[::1]/rss",
        "http://[::ffff:127.0.0.1]/rss",
    ],
    "authority_parser_confusion": [
        "http://rss.trustedsource.com\\@evil.test/rss",
        "http://rss.trustedsource.com%2eevil.test/rss",
        "http://evil.test\\rss.trustedsource.com/rss",
    ],
    "disallowed_scheme": [
        "ftp://rss.trustedsource.com/feed",
        "file://rss.trustedsource.com/etc/passwd",
        "gopher://feeds.provider.com/",
    ],
    "malformed_or_relative_url": [
        "//rss.trustedsource.com/feed",
        "https:////rss.trustedsource.com/feed",
        "http://",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        feed_address = fdp.PickValueInList(ATTACKS[family])
    else:
        import urllib.parse

        host = fdp.PickValueInList([
            "rss.trustedsource.com",
            "feeds.provider.com",
            "newsfeed.safesite.org",
        ])
        path = urllib.parse.quote(
            fdp.ConsumeUnicodeNoSurrogates(8),
            safe="",
        )
        scheme = fdp.PickValueInList(["http", "https"])
        feed_address = f"{scheme}://{host}/feed/{path}"

    return {"feed_address": feed_address}
