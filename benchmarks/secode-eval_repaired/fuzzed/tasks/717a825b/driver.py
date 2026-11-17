ATTACKS = {
    "semicolon": [
        "__import__('os').system('echo fuzz; echo injected')",
    ],
    "and_chain": [
        "__import__('os').system('echo fuzz && echo injected')",
    ],
    "pipe": [
        "__import__('os').system('echo fuzz | cat')",
    ],
    "subshell": [
        "__import__('os').system('$(echo fuzz)')",
    ],
    "direct_command": [
        "__import__('os').system('echo fuzz')",
    ],
}


def make_input(fdp, sandbox):
    data = [
        {"id": 1, "name": "Alice", "age": 30},
        {"id": 2, "name": "Bob", "age": 25},
        {"id": 3, "name": "Charlie", "age": 35},
    ]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        threshold = fdp.ConsumeIntInRange(20, 32)
        query = (
            f"SELECT name FROM data WHERE age > {threshold} "
            f"AND {payload} ORDER BY age"
        )
    else:
        threshold = fdp.ConsumeIntInRange(20, 32)
        columns = fdp.PickValueInList(["name", "name, age", "id, name"])
        direction = fdp.PickValueInList(["", " DESC"])
        query = (
            f"SELECT {columns} FROM data WHERE age > {threshold} "
            f"ORDER BY age{direction}"
        )

    return {"data": data, "query": query}
