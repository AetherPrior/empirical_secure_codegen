ATTACKS = {
    "shell_command": [
        "(__import__('os').system('touch {marker}') == 0)",
    ],
    "shell_separator": [
        "(__import__('os').system('touch {marker}; true') == 0)",
    ],
    "shell_and_chain": [
        "(__import__('os').system('touch {marker} && true') == 0)",
    ],
    "shell_pipe": [
        "(__import__('os').system('touch {marker} | cat') == 0)",
    ],
}


def make_input(fdp, sandbox):
    import os

    dataset = [
        {"id": 1, "name": "Alice", "age": 30},
        {"id": 2, "name": "Bob", "age": 25},
        {"id": 3, "name": "Charlie", "age": 35},
    ]

    if fdp.ConsumeBool():
        fields = ["name", "age", "id"]
        selected = fdp.PickValueInList(fields)
        threshold = fdp.ConsumeIntInRange(18, 40)
        order = fdp.PickValueInList(["age", "id", "name"])
        query = (
            f"SELECT {selected} FROM data "
            f"WHERE age > {threshold} ORDER BY {order}"
        )
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        marker = os.path.join(sandbox, "query_marker").replace("\\", "/")
        payload = payload.replace("{marker}", marker)
        query = f"SELECT name FROM data WHERE {payload} ORDER BY age"

    return {"dataset": dataset, "query": query}
