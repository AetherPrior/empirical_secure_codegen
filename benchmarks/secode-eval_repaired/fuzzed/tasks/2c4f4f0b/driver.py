ATTACKS = {
    "trusted_name_in_untrusted_host": [
        "https://rss.trustedsource.com.evil.example/rss",
        "https://evil-rss.trustedsource.com/feed",
        "https://rss.trustedsource.com.attacker.test/rss",
    ],
    "userinfo_host_confusion": [
        "https://rss.trustedsource.com@127.0.0.1/rss-feed",
        "https://feeds.provider.com@evil.example/feed",
        "https://evil.example@rss.trustedsource.com/feed",
    ],
    "untrusted_host_with_trusted_path_or_query": [
        "https://evil.example/rss.trustedsource.com",
        "https://evil.example/feed?source=feeds.provider.com",
    ],
    "internal_address": [
        "http://127.0.0.1/rss-feed",
        "http://localhost/feed",
        "http://10.1.2.3/rss",
        "http://192.168.1.10/rss",
    ],
    "alternate_internal_address": [
        "http://2130706433/rss",
        "http://0x7f000001/rss",
        "http://0177.0.0.1/rss",
    ],
    "ambiguous_url_syntax": [
        "https://evil.example\\@rss.trustedsource.com/feed",
        "https://rss.trustedsource.com\\@evil.example/feed",
        "https://rss.trustedsource.com./feed",
    ],
    "disallowed_scheme": [
        "file://rss.trustedsource.com/etc/passwd",
        "javascript://rss.trustedsource.com/feed",
    ],
}


def make_input(fdp, sandbox):
    benign = [
        "https://newsfeed.safesite.org/today",
        "https://rss.trustedsource.com/rss",
        "http://feeds.provider.com/latest",
    ]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        source_url = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            if suffix:
                source_url += "?q=" + suffix
    else:
        source_url = fdp.PickValueInList(benign)

    return {"source_url": source_url}
