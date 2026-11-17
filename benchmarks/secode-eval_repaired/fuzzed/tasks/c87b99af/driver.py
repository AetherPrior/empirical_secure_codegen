ATTACKS = {
    "python_os_system": [
        " AND __import__('os').system('echo hacked')",
    ],
    "shell_semicolon": [
        ' AND __import__("os").system("echo hacked; echo injected")',
    ],
    "shell_and_chain": [
        ' AND __import__("os").system("echo hacked && echo injected")',
    ],
    "boolean_short_circuit": [
        " OR __import__('os').system('echo hacked')",
    ],
}


def make_input(fdp, sandbox):
    records = [
        {"id": 1, "name": "Alice", "age": 30},
        {"id": 2, "name": "Bob", "age": 25},
        {"id": 3, "name": "Charlie", "age": 35},
    ]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        threshold = fdp.ConsumeIntInRange(20, 35)
        user_query = (
            f"SELECT name, age FROM data WHERE age > {threshold}"
            f"{payload} ORDER BY age"
        )
    else:
        field = fdp.PickValueInList(["name", "age", "id"])
        threshold = fdp.ConsumeIntInRange(20, 35)
        user_query = (
            f"SELECT name, age FROM data WHERE age > {threshold} ORDER BY {field}"
        )

    return {"records": records, "user_query": user_query}
