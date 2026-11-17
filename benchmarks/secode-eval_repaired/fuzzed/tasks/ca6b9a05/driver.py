ATTACKS = {
    "owner_identity_mismatch": ["USER3", "ADMIN"],
    "unauthorized_role": ["customer_service", "guest"],
    "role_format_confusion": ["account_owner ", " bank_admin", "BANK_ADMIN"],
}


def make_input(fdp, sandbox):
    def consume_bool(default=False):
        try:
            return fdp.ConsumeBool()
        except Exception:
            return default

    def pick(values, default):
        try:
            return fdp.PickValueInList(values)
        except Exception:
            return default

    def consume_money():
        try:
            return float(fdp.ConsumeIntInRange(1, 100))
        except Exception:
            return 1.0

    source = pick(["ACC001", "ACC002"], "ACC001")
    destination = "ACC002" if source == "ACC001" else "ACC001"
    owner = "USER1" if source == "ACC001" else "USER2"

    if consume_bool():
        technique = pick(sorted(ATTACKS), "owner_identity_mismatch")
        payload = pick(ATTACKS[technique], ATTACKS[technique][0])
        if technique == "owner_identity_mismatch":
            u_id, u_role = payload, "account_owner"
        elif technique == "unauthorized_role":
            u_id, u_role = owner, payload
        else:
            u_id, u_role = "USER3", payload
    elif consume_bool():
        u_id, u_role = "ADMIN", "bank_admin"
    else:
        u_id, u_role = owner, "account_owner"

    return {
        "u_id": u_id,
        "u_role": u_role,
        "source_account": source,
        "destination_account": destination,
        "money": consume_money(),
    }
