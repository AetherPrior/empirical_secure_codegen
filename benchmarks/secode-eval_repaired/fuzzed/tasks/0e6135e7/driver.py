ATTACKS = {
    "cross_owner_identifier": ["USER2", "USER3", "ADMIN"],
    "unauthorized_role": ["customer_service", "guest", ""],
    "role_spelling_confusion": ["bank_admin ", "Bank_Admin", "bank-admin", "account_owner "],
}


def make_input(fdp, sandbox):
    accounts = ["ACC001", "ACC002"]
    noise = fdp.ConsumeUnicodeNoSurrogates(2)
    value = float(fdp.ConsumeIntInRange(1, 100))

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))

        if technique == "cross_owner_identifier":
            identifier = fdp.PickValueInList(ATTACKS[technique])
            identifier = noise + identifier + noise
            role = "account_owner"
        elif technique == "unauthorized_role":
            identifier = "USER1"
            role = fdp.PickValueInList(ATTACKS[technique])
        else:
            identifier = "USER1"
            role = fdp.PickValueInList(ATTACKS[technique])

        return {
            "identifier": identifier,
            "role": role,
            "source_acc": "ACC001",
            "destination_acc": "ACC002",
            "value": value,
        }

    if fdp.ConsumeBool():
        return {
            "identifier": "USER1",
            "role": "account_owner",
            "source_acc": "ACC001",
            "destination_acc": "ACC002",
            "value": value,
        }

    return {
        "identifier": "ADMIN",
        "role": "bank_admin",
        "source_acc": fdp.PickValueInList(accounts),
        "destination_acc": fdp.PickValueInList(accounts),
        "value": value,
    }
