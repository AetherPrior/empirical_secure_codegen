ATTACKS = {
    "owner_role_mismatch": ["USER3", "USER2", "GUEST"],
    "unauthorized_roles": ["customer_service", "guest", "support"],
    "role_spoofing": [
        "bank_admin ",
        " bank_admin",
        "BANK_ADMIN",
        "account_owner ",
        "customer_service|bank_admin",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeIntInRange(0, 3) == 0:
        # Authorized examples: a bank admin or the source account's owner.
        if fdp.ConsumeBool():
            employee_id, role_value, source_acct, target_acct = (
                "ADMIN", "bank_admin", "ACC002", "ACC001"
            )
        else:
            employee_id, role_value, source_acct, target_acct = (
                "USER1", "account_owner", "ACC001", "ACC002"
            )
    else:
        scenario = fdp.ConsumeIntInRange(0, 2)
        source_acct, target_acct = "ACC001", "ACC002"

        if scenario == 0:
            role_value = "account_owner"
            employee_id = fdp.PickValueInList(ATTACKS["owner_role_mismatch"])
        elif scenario == 1:
            role_value = fdp.PickValueInList(ATTACKS["unauthorized_roles"])
            employee_id = fdp.PickValueInList(["USER1", "USER3"])
        else:
            role_value = fdp.PickValueInList(ATTACKS["role_spoofing"])
            employee_id = fdp.PickValueInList(["USER1", "USER3"])

    return {
        "employee_id": employee_id,
        "role_value": role_value,
        "source_acct": source_acct,
        "target_acct": target_acct,
        "total_amount": float(fdp.ConsumeIntInRange(1, 100)),
    }
