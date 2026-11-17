ATTACKS = {
    "role_case_confusion": ["Admin", "ADMIN", "administrator"],
    "role_boundary_confusion": ["admin ", " admin", "admin\t", "admin\x00"],
    "owner_claim_spoof": ["user7777", "*", ""],
    "order_id_confusion": ["order1234/../order5678", "order1234\x00"],
}


def make_input(fdp, sandbox):
    orders = [
        ("order1234", "user5678"),
        ("order5678", "user1234"),
    ]
    mode = fdp.ConsumeIntInRange(0, 5)

    if mode == 0:
        # Ordinary unauthorized access attempt.
        order_id, order_user_id = fdp.PickValueInList(orders)
        user_id, user_role = "user7777", "customer"

    elif mode == 1:
        # A role string that should not grant admin privileges.
        order_id, order_user_id = fdp.PickValueInList(orders)
        family = fdp.PickValueInList(
            ["role_case_confusion", "role_boundary_confusion"]
        )
        user_role = fdp.PickValueInList(ATTACKS[family])
        user_id = "user7777"

    elif mode == 2:
        # The supplied owner claim conflicts with the selected order's real owner.
        order_id, _actual_owner = fdp.PickValueInList(orders)
        user_id = "user7777"
        user_role = "customer"
        order_user_id = fdp.PickValueInList(ATTACKS["owner_claim_spoof"])

    elif mode == 3:
        # Exercise order lookup with a malformed or altered identifier.
        order_id = fdp.PickValueInList(ATTACKS["order_id_confusion"])
        order_user_id = "user5678"
        user_id, user_role = "user7777", "customer"

    elif mode == 4:
        # Benign authorized owner access.
        order_id, order_user_id = fdp.PickValueInList(orders)
        user_id, user_role = order_user_id, "customer"

    else:
        # Benign admin access.
        order_id, order_user_id = fdp.PickValueInList(orders)
        user_id, user_role = "user1234", "admin"

    if mode in (1, 2, 3) and fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])
        fuzz = fdp.ConsumeUnicodeNoSurrogates(2)
        if fdp.ConsumeBool():
            payload = fuzz + payload
        else:
            payload = payload + fuzz

        if family.startswith("role_"):
            user_role = payload
        elif family == "owner_claim_spoof":
            order_user_id = payload
        else:
            order_id = payload

    return {
        "user_id": user_id,
        "user_role": user_role,
        "order_id": order_id,
        "order_user_id": order_user_id,
    }
