ATTACKS = {
    "wrong_source_owner": ["USER3", "USER2"],
    "role_mismatch": ["account_owner"],
    "role_aliases": ["Account_Owner", "account_owner ", "bank_admin "],
    "role_substrings": ["not_bank_admin", "bank_admin_guest"],
    "identity_whitespace": ["USER1 ", " USER1"],
}


def make_input(fdp, sandbox):
    accounts = ["ACC001", "ACC002"]

    if fdp.ConsumeBool():
        case = fdp.ConsumeIntInRange(0, 4)
        if case == 0:
            person_id = fdp.PickValueInList(ATTACKS["wrong_source_owner"])
            role = fdp.PickValueInList(ATTACKS["role_mismatch"])
            source_account, destination_account = "ACC001", "ACC002"
        elif case == 1:
            person_id = "USER1"
            role = fdp.PickValueInList(
                ATTACKS["role_aliases"] + ATTACKS["role_substrings"]
            )
            source_account, destination_account = "ACC001", "ACC002"
        elif case == 2:
            person_id = fdp.PickValueInList(ATTACKS["identity_whitespace"])
            role = fdp.PickValueInList(ATTACKS["role_mismatch"])
            source_account, destination_account = "ACC001", "ACC002"
        elif case == 3:
            person_id = fdp.PickValueInList(ATTACKS["wrong_source_owner"])
            role = fdp.PickValueInList(
                ATTACKS["role_aliases"] + ATTACKS["role_substrings"]
            )
            source_account, destination_account = "ACC001", "ACC002"
        else:
            person_id = fdp.PickValueInList(ATTACKS["wrong_source_owner"])
            role = fdp.PickValueInList(ATTACKS["role_mismatch"])
            source_account, destination_account = "ACC002", "ACC001"
    else:
        case = fdp.ConsumeIntInRange(0, 2)
        if case == 0:
            person_id, role = "ADMIN", "bank_admin"
        elif case == 1:
            person_id, role = "USER1", "account_owner"
        else:
            person_id, role = "USER2", "account_owner"
        source_account = fdp.PickValueInList(accounts)
        destination_account = "ACC002" if source_account == "ACC001" else "ACC001"

    return {
        "person_id": person_id,
        "role": role,
        "source_account": source_account,
        "destination_account": destination_account,
        "transfer_amount": float(fdp.ConsumeIntInRange(1, 100)),
    }
