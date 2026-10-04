"""Sample HTTPS and UDP DNS connectivity; emit observations, not a policy verdict."""

import json
import secrets
import socket
import struct
import urllib.error
import urllib.request


def probe():
    results = {}
    for name, handler in (("https_environment_proxy", urllib.request.ProxyHandler()),
                          ("https_direct", urllib.request.ProxyHandler({}))):
        try:
            opener = urllib.request.build_opener(handler)
            with opener.open("https://registry.npmjs.org/", timeout=5) as response:
                results[name] = {"http_status": response.status}
        except urllib.error.HTTPError as error:
            results[name] = {"http_status": error.code}
        except Exception as error:
            # Proxy configuration and exception text may contain credentials.
            reason = getattr(error, "reason", error)
            results[name] = {"error_type": type(error).__name__,
                             "reason_type": type(reason).__name__,
                             "errno": getattr(reason, "errno", None),
                             "tls_verify_code": getattr(reason, "verify_code", None)}
    transaction = secrets.token_bytes(2)
    question = b"".join(bytes([len(label)]) + label for label in b"registry.npmjs.org".split(b"."))
    packet = transaction + struct.pack("!HHHHH", 0x100, 1, 0, 0, 0) + question + b"\0\0\1\0\1"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.connect(("1.1.1.1", 53))
            sock.send(packet)
            data = sock.recv(4096)
        valid = len(data) >= 12 and data[:2] == transaction and bool(data[2] & 0x80)
        results["udp_dns"] = {"valid_response": valid,
                              "rcode": data[3] & 15 if valid else None}
    except Exception as error:
        results["udp_dns"] = {"error_type": type(error).__name__}
    return results


if __name__ == "__main__":
    print(json.dumps(probe(), sort_keys=True))
