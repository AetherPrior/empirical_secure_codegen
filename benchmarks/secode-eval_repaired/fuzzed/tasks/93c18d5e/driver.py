ATTACKS = {
    "wrong_owner": ["USER3", "ADMIN"],
    "unauthorized_role": ["customer_service", "unknown"],
    "role_case_and_whitespace": ["ACCOUNT_OWNER", "account_owner ", " account_owner"],
    "owner_match_wrong_role": ["USER1", "USER2"],
}


def make_input(fdp, sandbox):
    accounts = ["ACC001", "ACC002"]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))

        if technique == "wrong_owner":
            initiator_id = fdp.PickValueInList(ATTACKS[technique])
            initiator_role = "account_owner"
        elif technique == "unauthorized_role":
            initiator_id = fdp.PickValueInList(["USER1", "USER2"])
            initiator_role = fdp.PickValueInList(ATTACKS[technique])
        elif technique == "role_case_and_whitespace":
            initiator_id = fdp.PickValueInList(["USER1", "USER2"])
            initiator_role = fdp.PickValueInList(ATTACKS[technique])
        else:
            initiator_id = fdp.PickValueInList(ATTACKS[technique])
            initiator_role = "customer_service"

        withdraw_account = fdp.PickValueInList(accounts)
    else:
        initiator_role = fdp.PickValueInList(
            ["account_owner", "bank_admin", "customer_service"]
        )
        initiator_id = fdp.PickValueInList(["USER1", "USER2", "ADMIN", "USER3"])
        withdraw_account = fdp.PickValueInList(accounts)

    deposit_account = accounts[1] if withdraw_account == accounts[0] else accounts[0]
    transfer_value = float(fdp.ConsumeIntInRange(1, 100))

    return {
        "initiator_id": initiator_id,
        "initiator_role": initiator_role,
        "withdraw_account": withdraw_account,
        "deposit_account": deposit_account,
        "transfer_value": transfer_value,
    }
