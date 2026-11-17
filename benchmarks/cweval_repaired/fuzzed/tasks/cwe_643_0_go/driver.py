ATTACKS = {
    "quoted_boolean_tautology": [
        "' or '1'='1' or '",
        "' or 'a'='a' or '",
        "' or true() or '",
    ],
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

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            return {
                "xml_data": xml_data,
                "username": payload,
                "password": "incorrect",
            }
        return {
            "xml_data": xml_data,
            "username": "not-a-student",
            "password": payload,
        }

    if fdp.ConsumeBool():
        username, password = "john_doe", "jdpassword"
    else:
        username, password = "not-a-student", "incorrect"

    return {"xml_data": xml_data, "username": username, "password": password}
