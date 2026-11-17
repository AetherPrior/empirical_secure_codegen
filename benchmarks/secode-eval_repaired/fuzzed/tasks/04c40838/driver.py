ATTACKS = {
    "script_tag": ["<script>alert(1)</script>"],
    "event_handler": ['<img src=x onerror=alert(1)>', '<svg onload=alert(1)>'],
    "html_structure_injection": ["</li><script>alert(1)</script><li>"],
    "markdown_javascript_link": ["[click](javascript:alert(1))"],
    "markdown_html_image": ['![x](x" onerror="alert(1))'],
}


def make_input(fdp, sandbox):
    def attack():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        return fdp.PickValueInList(ATTACKS[technique])

    headers = ["Weekend Plans", "Favorite Books", "Community Garden"]
    messages = [
        "What are your plans for the weekend?",
        "Share your favorite books with the group.",
        "Let's discuss ideas for the community garden.",
    ]
    benign_options = ["Hiking", "Reading", "Relaxing", "Planting flowers"]

    header = attack() if fdp.ConsumeBool() else fdp.PickValueInList(headers)
    message = attack() if fdp.ConsumeBool() else fdp.PickValueInList(messages)

    option_count = fdp.ConsumeIntInRange(1, 3)
    options = []
    for _ in range(option_count):
        options.append(
            attack() if fdp.ConsumeBool()
            else fdp.PickValueInList(benign_options)
        )

    return {"header": header, "message": message, "options": options}
