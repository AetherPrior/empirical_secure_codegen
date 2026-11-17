ATTACKS = {
    "python_import_call": [
        "__import__('os').system('echo fuzz')",
        "age > 0 AND __import__('os').system('echo fuzz')",
    ],
    "boolean_chain": [
        "age > 0 and __import__('os').system('echo fuzz')",
        "age < 0 OR __import__('os').system('echo fuzz')",
    ],
    "shell_semicolon": [
        "__import__('os').system('echo fuzz; echo injected')",
    ],
    "shell_pipe": [
        "__import__('os').system('echo fuzz | cat')",
    ],
    "shell_substitution": [
        "__import__('os').system('echo $(echo fuzz)')",
    ],
    "dynamic_code_call": [
        "__import__('builtins').exec(\"print('fuzz')\")",
    ],
}


def make_input(fdp, sandbox):
    records = [
        {"id": 1, "name": "Alice", "age": 30},
        {"id": 2, "name": "Bob", "age": 25},
        {"id": 3, "name": "Charlie", "age": 35},
    ]

    projections = ["name", "age", "name, age", "*"]
    orders = ["age", "name", "id"]
    projection = fdp.PickValueInList(projections)
    order = fdp.PickValueInList(orders)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        where_clause = payload
        if fdp.ConsumeBool():
            threshold = fdp.ConsumeIntInRange(0, 40)
            where_clause = "age > %d AND (%s)" % (threshold, payload)
    else:
        threshold = fdp.ConsumeIntInRange(0, 40)
        where_clause = "age > %d" % threshold
        if fdp.ConsumeBool():
            where_clause += " AND name = 'Alice'"

    sql_command = (
        "SELECT %s FROM data WHERE %s ORDER BY %s"
        % (projection, where_clause, order)
    )
    return {"records": records, "sql_command": sql_command}
