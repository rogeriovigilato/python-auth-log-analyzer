import os
import socket
import stat
import threading
import unittest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

import discovery

ISO_LINE = (
    "2026-10-14T20:00:12.183014-03:00 host sshd[2421]: "
    "Failed password for invalid user admin "
    "from 203.0.113.77 port 51201 ssh2"
)


class TestSniffLog(unittest.TestCase):
    def test_file_with_events_ranks_above_other_logs(self):
        with TemporaryDirectory() as directory:
            with_events = Path(directory) / "auth.log"
            with_events.write_text(
                ISO_LINE + "\n" + ISO_LINE + "\n",
                encoding="utf-8",
            )
            without_events = Path(directory) / "syslog"
            without_events.write_text(
                "nota: sshd[1]: Connection closed by 203.0.113.9\n",
                encoding="utf-8",
            )

            report = discovery.discover(
                candidates=[without_events, with_events],
                reference=datetime(2026, 10, 16),
                probe_service=False,
            )

        self.assertEqual(report["best_log"], str(with_events))

        summaries = {log["path"]: log for log in report["logs"]}
        self.assertEqual(
            summaries[str(with_events)]["parsed_events"], 2
        )
        self.assertEqual(summaries[str(with_events)]["rank"], 0)
        self.assertEqual(summaries[str(without_events)]["rank"], 1)

    def test_missing_file_is_reported_as_absent(self):
        with TemporaryDirectory() as directory:
            missing = Path(directory) / "auth.log"

            summary = discovery.sniff_log(missing)

        self.assertFalse(summary["exists"])
        self.assertIsNone(summary["rank"])

    @unittest.skipIf(
        os.geteuid() == 0,
        "root ignora permissões de leitura",
    )
    def test_file_without_permission_is_unreadable(self):
        with TemporaryDirectory() as directory:
            blocked = Path(directory) / "auth.log"
            blocked.write_text(ISO_LINE + "\n", encoding="utf-8")
            blocked.chmod(0)

            try:
                summary = discovery.sniff_log(blocked)
            finally:
                blocked.chmod(0o600)

        self.assertTrue(summary["exists"])
        self.assertFalse(summary["readable"])
        self.assertIsNone(summary["rank"])


class TestListeningPorts(unittest.TestCase):
    def test_extracts_only_listening_ports(self):
        tcp = (
            "  sl  local_address rem_address   st\n"
            "   0: 00000000:0016 00000000:0000 0A 0 0 0 0\n"
            "   1: 0100007F:1F90 00000000:0000 0A 0 0 0 0\n"
            "   2: 00000000:0050 0100007F:9C40 01 0 0 0 0\n"
        )

        ports = discovery.parse_listening_ports(tcp)

        self.assertEqual(ports, {22, 8080})


class TestBanner(unittest.TestCase):
    def test_grabs_ssh_banner_from_local_socket(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            connection, _ = server.accept()
            try:
                connection.sendall(b"SSH-2.0-Test\r\n")
            finally:
                connection.close()
                server.close()

        thread = threading.Thread(target=serve)
        thread.start()

        try:
            banner = discovery.grab_ssh_banner(port)
        finally:
            thread.join(timeout=5)

        self.assertEqual(banner, "SSH-2.0-Test")

    def test_non_ssh_service_returns_none(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            connection, _ = server.accept()
            try:
                connection.sendall(b"HTTP/1.0 400 Bad Request\r\n")
            finally:
                connection.close()
                server.close()

        thread = threading.Thread(target=serve)
        thread.start()

        try:
            banner = discovery.grab_ssh_banner(port)
        finally:
            thread.join(timeout=5)

        self.assertIsNone(banner)


class TestConfig(unittest.TestCase):
    def test_save_and_load_roundtrip(self):
        with TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            data = {"input": "/var/log/auth.log", "format": "iso"}

            discovery.save_config(data, path=config)

            self.assertEqual(discovery.load_config(path=config), data)

    def test_saved_config_is_private(self):
        with TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"

            discovery.save_config({"input": "x"}, path=config)

            mode = stat.S_IMODE(config.stat().st_mode)

        self.assertEqual(mode, 0o600)

    def test_missing_config_returns_none(self):
        with TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"

            self.assertIsNone(discovery.load_config(path=config))

    def test_invalid_config_returns_none(self):
        with TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text("isso não é json", encoding="utf-8")

            self.assertIsNone(discovery.load_config(path=config))


if __name__ == "__main__":
    unittest.main()
