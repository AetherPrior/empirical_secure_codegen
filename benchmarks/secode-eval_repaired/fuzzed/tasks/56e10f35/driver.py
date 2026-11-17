ATTACKS = {
    "owner_identity_mismatch": ["USER3", "USER2"],
    "unauthorized_role": ["customer_service", "support"],
    "role_spelling_confusion": ["Account_owner", "account_owner ", "bank_admin "],
}


def make_input(fdp, sandbox):
    accounts = [
        ("ACC001", "ACC002", "USER1"),
        ("ACC002", "ACC001", "USER2"),
    ]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        withdraw, deposit, owner = fdp.PickValueInList(accounts)

        if technique == "owner_identity_mismatch":
            initiator_id = payload
            position = "account_owner"
        elif technique == "unauthorized_role":
            initiator_id = owner
            position = payload
        else:
            initiator_id = "USER3"
            position = payload
    else:
        withdraw, deposit, owner = fdp.PickValueInList(accounts)
        if fdp.ConsumeBool():
            initiator_id, position = owner, "account_owner"
        else:
            initiator_id, position = "ADMIN", "bank_admin"

    transfer_value = float(fdp.PickValueInList([1, 10, 50, 100]))
    return {
        "initiator_id": initiator_id,
        "position": position,
        "withdraw_account": withdraw,
        "deposit_account": deposit,
        "transfer_value": transfer_value,
    }
