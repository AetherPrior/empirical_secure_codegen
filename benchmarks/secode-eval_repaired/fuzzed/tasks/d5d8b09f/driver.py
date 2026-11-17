ATTACKS = {
    "owner_mismatch": ["USER2", "USER3"],
    "role_alias": ["admin", "BANK_ADMIN", "bank_admin "],
    "unsupported_role": ["guest", "user", "account_owner "],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        # Authorized transfers: valid source owner or bank administrator.
        if fdp.ConsumeBool():
            return {
                "account_holder": "USER1",
                "user_role": "account_owner",
                "withdrawal_account": "ACC001",
                "receiving_account": "ACC002",
                "fund_amount": float(fdp.ConsumeIntInRange(1, 20)),
            }
        return {
            "account_holder": "ADMIN",
            "user_role": "bank_admin",
            "withdrawal_account": "ACC002",
            "receiving_account": "ACC001",
            "fund_amount": float(fdp.ConsumeIntInRange(1, 20)),
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])
    if fdp.ConsumeBool():
        payload += fdp.ConsumeUnicodeNoSurrogates(2)

    if technique == "owner_mismatch":
        account_holder, user_role = payload, "account_owner"
    elif technique == "role_alias":
        account_holder, user_role = "USER3", payload
    else:
        account_holder, user_role = "USER1", payload

    return {
        "account_holder": account_holder,
        "user_role": user_role,
        "withdrawal_account": "ACC001",
        "receiving_account": "ACC002",
        "fund_amount": float(fdp.ConsumeIntInRange(1, 20)),
    }
