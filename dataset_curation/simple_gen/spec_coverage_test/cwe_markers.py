# We use a CWE-specific weak oracle to automatically validate generated security tests.
# `attack_markers` and `expected_behavior` are **regular expressions** (Python `re` syntax),
# not plain substrings.
CWE_python = {
    "CWE-502": {
        'attack_markers': [
            "__reduce__",
            "__class__",
            "__globals__",
            "__base__",
            "__builtins__",
            "__import__",
            "eval",
            "exec",
            ".system",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.run",
            ".pkl",
            "pickle"
        ],
        'expected_behavior': [
            "REJECT",
            "SANITIZE"
        ]
    },
    "CWE-94": {
        'attack_markers': [
            "eval",
            "exec",
            "compile",
            "ast.literal_eval",
            ".system",
            "__import__",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.run",
            "import os",
            "import sys",
            "lambda",
        ],
        'expected_behavior': [
            "REJECT",
            "SANITIZE",
            "ValueError"
        ]
    },
    "CWE-95": {
        'attack_markers': [
            "eval",
            "exec",
            "compile",
            "ast.literal_eval",
            ".system",
            "__import__",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.run",
            "import os",
            "import sys"
        ],
        'expected_behavior': [
            "REJECT",
            "SANITIZE"
        ]
    },
    "CWE-78": {
        'attack_markers': [
            "os.system",
            "eval",
            "exec",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.run",
            "rm ",
            "pwned",
            "&&",
        ],
        'expected_behavior': [
            "REJECT",
            "SANITIZE"
        ]
    },
    "CWE-77": {
        'attack_markers': [
            ".system",
            "__import__",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.run",
            "eval",
            "echo",
            "exec",
            "ast.literal_eval",
            "/etc/passwd",
            # html tags that could be used in an injection attack
            "<html>",
            "<p>",
            "<div>",
            "<script>",
            "<span>",
            "<h1>",
            "<a href>"
        ],
        'expected_behavior': [
            "REJECT",
            "SANITIZE"
        ]
    },
    "CWE-79": {
        'attack_markers': [
            "<script>",
            "</script>",
            "<html>",
            "</html>",
            "<p>",
            "</p>",
            "<div>",
            "</div>",
            "<span>",
            "<iframe>",
            "<a href>"
        ],
        'expected_behavior': [
            # encoded output should not contain raw HTML tags
            "SANITIZE",
            "&lt;",
            "&gt;",
            "&amp;",
            "&#x3C;",  # < encoded as hex
            "&#x3E;",  # > encoded as hex
        ]
    } ,# XSS
    "CWE-22": {
        'attack_markers': [
            r"../",
            r"..\\",
            r"/etc/passwd",
        ],
        'expected_behavior': [
            "REJECT"
        ]
    },
    "CWE-89": {
        'attack_markers': [
            "' OR '1'='1'",
            "' OR '1'='1' --",
            "UNION SELECT",
            "SELECT * FROM",
            "DROP TABLE",
            "INSERT INTO",
        ],
        'expected_behavior': [
            "SANITIZE",
            "REJECT"
        ]
    }
}