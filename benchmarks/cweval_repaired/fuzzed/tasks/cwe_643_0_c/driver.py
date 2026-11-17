ATTACKS = {
    "username_boolean_or": ["alice' or '1'='1"],
    "password_boolean_or": ["' or '1'='1"],
}


def make_input(fdp, sandbox):
    xml_data = """<students>
  <student>
    <username>alice</username>
    <password>correct</password>
    <name>Alice Example</name>
    <citizenship>Canada</citizenship>
    <age>21</age>
  </student>
  <student>
    <username>bob</username>
    <password>secret</password>
    <name>Bob Example</name>
    <citizenship>USA</citizenship>
    <age>22</age>
  </student>
</students>"""

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if technique == "username_boolean_or":
            username = payload + fdp.PickValueInList(["", " "])
            password = "wrong"
        else:
            username = "alice"
            password = payload
    else:
        username = fdp.PickValueInList(["alice", "bob", "unknown"])
        password = fdp.PickValueInList(["correct", "secret", "wrong"])

    return {
        "xml_data": xml_data,
        "username": username,
        "password": password,
    }
