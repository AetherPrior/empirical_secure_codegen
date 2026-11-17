ATTACKS = {
    "owner_mismatch": ["USER3"],
    "unauthorized_role": ["customer_service", "guest"],
    "role_confusion": ["ACCOUNT_OWNER", "account_owner ", " bank_admin"],
}


def make_input(fdp, sandbox):
    accounts = ["ACC001", "ACC002"]
    from_account = fdp.PickValueInList(accounts)
    to_account = "ACC002" if from_account == "ACC001" else "ACC001"
    owner_id = "USER1" if from_account == "ACC001" else "USER2"
    amount = float(fdp.ConsumeIntInRange(1, 100))

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique == "owner_mismatch":
            user_id = payload
            user_role = "account_owner"
        else:
            user_id = owner_id
            user_role = payload

        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(2)
            if fdp.ConsumeBool():
                user_id = fuzz + user_id
            else:
                user_id = user_id + fuzz
    else:
        if fdp.ConsumeBool():
            user_id = owner_id
            user_role = "account_owner"
        else:
            user_id = "ADMIN"
            user_role = "bank_admin"

    return {
        "user_id": user_id,
        "user_role": user_role,
        "from_account": from_account,
        "to_account": to_account,
        "amount": amount,
    }
