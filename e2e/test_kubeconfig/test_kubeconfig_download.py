"""
Testing kubeconfig download with a fake assisted-service API server.
"""
# pylint: disable=redefined-outer-name,missing-class-docstring,missing-function-docstring
# pylint: disable=invalid-name,redefined-builtin,global-statement,subprocess-run-check

import subprocess
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json
import re

import pytest

CLUSTER_ID = "11111111-1111-1111-1111-111111111111"

_next_port = 9510


def _make_handler(available, start_time):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path
            qs = parse_qs(parsed.query)

            if path == "/api/assisted-install/v2/clusters":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        [
                            {
                                "id": CLUSTER_ID,
                                "name": "test-cluster",
                                "status": "installed",
                                "base_dns_domain": "test.example.com",
                                "kind": "Cluster",
                                "openshift_version": "4.17",
                                "high_availability_mode": "Full",
                            }
                        ]
                    ).encode()
                )
                return

            m = re.match(
                r"/api/assisted-install/v2/clusters/([^/]+)/downloads/credentials$",
                path,
            )
            if m:
                file_name = qs.get("file_name", [None])[0]
                elapsed = time.monotonic() - start_time
                if file_name in available and elapsed >= available[file_name]:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.end_headers()
                    self.wfile.write(f"# fake {file_name} content\n".encode())
                else:
                    self.send_response(409)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(
                        json.dumps(
                            {"code": "409", "reason": f"{file_name} not available"}
                        ).encode()
                    )
                return

            self.send_response(404)
            self.end_headers()

        def log_message(self, format, *args):
            pass

    return Handler


def _make_fixture(**variants):
    @pytest.fixture
    def f():
        global _next_port
        port = _next_port
        _next_port += 1
        handler = _make_handler(variants, time.monotonic())
        server = HTTPServer(("127.0.0.1", port), handler)
        server.allow_reuse_address = True
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        yield port
        server.shutdown()

    return f


both = _make_fixture(kubeconfig=0, **{"kubeconfig-noingress": 0})
only_noingress = _make_fixture(**{"kubeconfig-noingress": 0})
only_regular = _make_fixture(kubeconfig=0)
nothing = _make_fixture()
noingress_after_3s = _make_fixture(**{"kubeconfig-noingress": 3})
regular_after_3s = _make_fixture(kubeconfig=3)


def aicli(port, *extra, timeout=5):
    return subprocess.run(
        [
            "aicli",
            "-u",
            f"http://127.0.0.1:{port}",
            "download",
            "kubeconfig",
            "-s",
            *extra,
            "test-cluster",
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def test_both_available(both):
    r = aicli(both)
    assert r.returncode == 0
    assert "# fake kubeconfig content" in r.stdout
    assert "falling back" not in r.stdout


def test_only_noingress_fallback(only_noingress):
    r = aicli(only_noingress)
    assert r.returncode == 0
    assert "# fake kubeconfig-noingress content" in r.stdout
    assert "falling back" in r.stdout


def test_only_noingress_no_fallback(only_noingress):
    r = aicli(only_noingress, "--no-noingress")
    assert r.returncode == 1
    assert "not yet available" in r.stdout


def test_only_regular(only_regular):
    r = aicli(only_regular)
    assert r.returncode == 0
    assert "# fake kubeconfig content" in r.stdout
    assert "falling back" not in r.stdout


def test_wait_with_noingress_available(only_noingress):
    r = aicli(only_noingress, "--wait")
    assert r.returncode == 0
    assert "# fake kubeconfig-noingress content" in r.stdout
    assert "falling back" in r.stdout


def test_wait_noingress_appears(noingress_after_3s):
    r = aicli(noingress_after_3s, "--wait", timeout=15)
    assert r.returncode == 0
    assert "# fake kubeconfig-noingress content" in r.stdout
    assert "falling back" in r.stdout


def test_wait_no_noingress_regular_appears(regular_after_3s):
    r = aicli(regular_after_3s, "--wait", "--no-noingress", timeout=15)
    assert r.returncode == 0
    assert "# fake kubeconfig content" in r.stdout
    assert "falling back" not in r.stdout


def test_wait_nothing_times_out(nothing):
    with pytest.raises(subprocess.TimeoutExpired):
        aicli(nothing, "--wait", timeout=8)


def test_wait_no_noingress_nothing_times_out(nothing):
    with pytest.raises(subprocess.TimeoutExpired):
        aicli(nothing, "--wait", "--no-noingress", timeout=8)
