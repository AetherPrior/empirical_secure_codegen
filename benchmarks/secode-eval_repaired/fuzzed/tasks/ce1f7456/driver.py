ATTACKS = {
    "unapproved_hosts": [
        "https://evil.com/hack",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/",
    ],
    "allowlist_suffix_confusion": [
        "https://partner.com.evil.com/",
        "https://trusted-redirect.com.evil.com/",
        "https://partner.com:443.evil.com/",
    ],
    "userinfo_host_confusion": [
        "https://partner.com@evil.com/",
        "https://trusted-redirect.com@evil.com/",
    ],
    "scheme_relative_urls": [
        "//evil.com/path",
        "///evil.com/path",
    ],
    "parser_disagreement": [
        "https://partner.com\\@evil.com/",
        "https://partner.com%2Eevil.com/",
        "https://partner.com%00.evil.com/",
        "https://partner.com./",
    ],
    "unsafe_schemes": [
        "javascript://evil.com/%0aalert(1)",
        "file:///etc/passwd",
        "data:text/html,<script>alert(1)</script>",
    ],
}


def make_input(fdp, sandbox):
    benign = [
        "https://partner.com/welcome",
        "https://trusted-redirect.com/continue",
        "https://partner.com/",
    ]

    if not fdp.ConsumeBool():
        return {"destination_url": fdp.PickValueInList(benign)}

    family = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[family])

    # Add small fuzzed query text while retaining the selected attack URL.
    if fdp.ConsumeBool():
        text = fdp.ConsumeUnicodeNoSurrogates(8)
        payload += "?q=" + text

    return {"destination_url": payload}
