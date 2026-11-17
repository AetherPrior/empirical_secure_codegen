ATTACKS = {
    "username_boolean_or": ["' or '1'='1' or username='"],
    "username_true_predicate": ["nobody' or '1'='1"],
    "password_boolean_or": ["wrong' or '1'='1"],
    "password_targeted_or": ["wrong' or username='john_doe"],
}


def make_input(fdp, sandbox):
    xml_data = """<students>
    <student>
        <username>john_doe</username>
        <password>jdpassword</password>
        <name>John Doe</name>
        <citizenship>USA</citizenship>
        <age>25</age>
    </student>
    <student>
        <username>bob_smith</username>
        <password>bspassword</password>
        <name>Bob Smith</name>
        <citizenship>Canada</citizenship>
        <age>22</age>
    </student>
</students>"""

    benign_pairs = [
        ("john_doe", "jdpassword"),
        ("bob_smith", "bspassword"),
        ("unknown", "invalid"),
    ]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique.startswith("username_"):
            username = payload
            password = fdp.PickValueInList(["jdpassword", "bspassword", "invalid"])
        else:
            username = "john_doe"
            password = payload
    else:
        username, password = fdp.PickValueInList(benign_pairs)

    return {
        "xml_data": xml_data,
        "username": username,
        "password": password,
    }
