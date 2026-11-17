ATTACKS = {
    "cross_account_owner": ["USER2", "USER3"],
    "unauthorized_role": ["customer_service", "guest", "BANK_ADMIN", "account_owner ", "bank_admin "],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        if technique == "cross_account_owner":
            u_identifier = fdp.PickValueInList(ATTACKS[technique])
            u_role = "account_owner"
        else:
            u_identifier = "USER1"
            u_role = fdp.PickValueInList(ATTACKS[technique])

        account_from, account_to = "ACC001", "ACC002"
    else:
        if fdp.ConsumeBool():
            u_identifier, u_role = "USER1", "account_owner"
            account_from, account_to = "ACC001", "ACC002"
        elif fdp.ConsumeBool():
            u_identifier, u_role = "USER2", "account_owner"
            account_from, account_to = "ACC002", "ACC001"
        else:
            u_identifier, u_role = "ADMIN", "bank_admin"
            account_from, account_to = "ACC002", "ACC001"

    transfer_amount = float(fdp.ConsumeIntInRange(1, 200))
    return {
        "u_identifier": u_identifier,
        "u_role": u_role,
        "account_from": account_from,
        "account_to": account_to,
        "transfer_amount": transfer_amount,
    }
