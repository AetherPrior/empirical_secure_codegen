ATTACKS = {
    "owner_mismatch": ["USER2", "USER3", "ADMIN"],
    "unauthorized_role": ["customer_service", "admin", "support"],
    "role_case_or_whitespace": ["BANK_ADMIN", "Account_owner", "bank_admin "],
}


def make_input(fdp, sandbox):
    accounts = ["ACC001", "ACC002"]
    amount = float(fdp.ConsumeIntInRange(1, 100))

    if fdp.ConsumeBool():
        # Benign owner transfer or authorized bank-admin transfer.
        if fdp.ConsumeBool():
            return {
                "uid": "USER1",
                "role": "account_owner",
                "source_account": "ACC001",
                "destination_account": "ACC002",
                "transfer_amount": amount,
            }
        return {
            "uid": "ADMIN",
            "role": "bank_admin",
            "source_account": "ACC002",
            "destination_account": "ACC001",
            "transfer_amount": amount,
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])
    fuzz = fdp.ConsumeUnicodeNoSurrogates(2)

    if technique == "owner_mismatch":
        uid = payload if fdp.ConsumeBool() else fuzz + payload
        role = "account_owner"
    else:
        uid = "USER1"
        role = payload if fdp.ConsumeBool() else payload + fuzz

    source = fdp.PickValueInList(accounts)
    destination = "ACC002" if source == "ACC001" else "ACC001"

    return {
        "uid": uid,
        "role": role,
        "source_account": source,
        "destination_account": destination,
        "transfer_amount": amount,
    }
