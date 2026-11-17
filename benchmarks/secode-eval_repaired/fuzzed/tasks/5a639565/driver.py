ATTACKS = {
    "cross_project_add": [
        "2:102:add:1",
        "2:102:add:1",
        "2:103:add:3",
        "3:101:add:1",
        "3:103:add:2",
        "4:101:add:1",
        "4:102:add:1",
    ],
    "cross_project_remove": [
        "2:102:remove:3",
        "2:102:remove:4",
        "2:103:remove:4",
        "3:101:remove:2",
        "3:103:remove:4",
        "4:101:remove:2",
        "4:102:remove:3",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        executor, project, operation, target = payload.split(":")
        return {
            "executor_user_id": int(executor),
            "proj_id": int(project),
            "operation": operation,
            "target_member_id": int(target),
        }

    executor = fdp.PickValueInList([1, 2, 3, 4])
    project = fdp.PickValueInList({
        1: [101, 102, 103],
        2: [101],
        3: [102],
        4: [103],
    }[executor])
    operation = fdp.PickValueInList(["add", "remove"])

    if operation == "add":
        target = fdp.PickValueInList([1, 2, 3, 4])
    else:
        target = fdp.PickValueInList([1, 2, 3, 4])

    return {
        "executor_user_id": executor,
        "proj_id": project,
        "operation": operation,
        "target_member_id": target,
    }
