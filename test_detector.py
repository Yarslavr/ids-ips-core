import json
from core.signature_engine import SignatureEngine


def run_tests():
    with open("config/rules.json", "r", encoding="utf-8") as f:
        config = json.load(f)

    engine = SignatureEngine(config["signatures"])

    # Набор тестов: (payload, protocol, dst_port, описание)
    test_cases = [
        (
            "GET /index.html HTTP/1.1\r\nHost: test.local\r\n\r\n",
            "tcp",
            80,
            "Легитимный веб-запрос"
        ),
        (
            "GET /items?cat=1 UNION SELECT null, pass FROM users-- HTTP/1.1",
            "tcp",
            80,
            "SQL Injection (UNION SELECT)"
        ),
        (
            "POST /login HTTP/1.1\r\n\r\nuser=admin' OR 1=1--",
            "tcp",
            80,
            "SQL Injection (OR 1=1)"
        ),
        (
            "GET /view?path=../../../../etc/passwd HTTP/1.1",
            "tcp",
            80,
            "Path Traversal (/etc/passwd)"
        ),
        (
            "GET /search?text=<script>alert('pwn')</script> HTTP/1.1",
            "tcp",
            80,
            "XSS Injection"
        ),
        (
            "POST /api/exec HTTP/1.1\r\n\r\ncmd=ping; whoami",
            "tcp",
            80,
            "RCE (Command Injection)"
        ),
        (
            "GET /items?cat=1 UNION SELECT 1,2 HTTP/1.1",
            "tcp",
            443,
            "SQLi на порту 443 (в правиле 1001 задан порт 80 — должно быть пропущено)"
        )
    ]

    for payload, proto, port, label in test_cases:
        is_threat, action, info = engine.check(payload, protocol=proto, dst_port=port)
        status = f"[\033[91m{action.upper()}\033[0m]" if is_threat else "[\033[92mACCEPT\033[0m]"
        print(f"{status} {label}")
        if is_threat:
            print(f"       └── ID: {info['rule_id']} | {info['name']} | MITRE: {info['mitre']} | Severity: {info['severity']}")
        print("-" * 70)


if __name__ == "__main__":
    run_tests()