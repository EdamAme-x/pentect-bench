#!/usr/bin/env python3
"""Local-only client copied into each benchmark project.

The hostname is only an HTTP Host header. The TCP destination is always
127.0.0.1; this script cannot contact Stripe or an email provider.
"""
from __future__ import annotations

import argparse
import http.client
import json


SERVICES = {
    "mail": ("mail.example.sandbox", "/v1/messages",
             {"to": "recipient@example.invalid", "subject": "Pentect benchmark"}),
    "payment": ("api.stripe.com.sandbox", "/v1/payment_intents",
                {"amount": 700, "currency": "jpy", "payment_method": "pm_bench_ok"}),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=SERVICES)
    parser.add_argument("port", type=int)
    parser.add_argument("token")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be a valid TCP port")
    host, path, payload = SERVICES[args.service]
    connection = http.client.HTTPConnection("127.0.0.1", args.port, timeout=10)
    try:
        connection.request(
            "POST", path, body=json.dumps(payload).encode(),
            headers={"Host": host, "Authorization": "Bearer " + args.token,
                     "Content-Type": "application/json"},
        )
        response = connection.getresponse()
        response.read()
        print("accepted" if response.status == 200 else "rejected")
        return 0 if response.status == 200 else 1
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
