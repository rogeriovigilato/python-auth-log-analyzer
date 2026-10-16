import json
import os
import socket
from datetime import datetime
from pathlib import Path

from analyzer import match_line

DEFAULT_AUTH_LOG_CANDIDATES = (
    "/var/log/auth.log",
    "/var/log/auth.log.1",
    "/var/log/secure",
    "/var/log/secure.1",
)

SNIFF_LINE_LIMIT = 200
PROBE_TIMEOUT = 0.4
FALLBACK_PORTS = (22, 2222)


def sniff_log(log_path, line_limit=SNIFF_LINE_LIMIT, reference=None):
    """Examina as primeiras linhas e resume o conteúdo do log."""
    summary = {
        "path": str(log_path),
        "exists": False,
        "readable": False,
        "total_lines": 0,
        "sshd_lines": 0,
        "parsed_events": 0,
        "formats": [],
        "rank": None,
        "error": None,
    }

    path = Path(log_path)

    if not path.is_file():
        return summary

    summary["exists"] = True

    if not os.access(path, os.R_OK):
        summary["error"] = "sem permissão de leitura"
        return summary

    formats = set()

    try:
        with path.open(encoding="utf-8", errors="replace") as log_file:
            for line in log_file:
                if summary["total_lines"] >= line_limit:
                    break

                summary["total_lines"] += 1

                if "sshd[" in line:
                    summary["sshd_lines"] += 1

                name, event = match_line(
                    line.rstrip("\n"),
                    reference=reference,
                )

                if name is not None:
                    formats.add(name)

                if event is not None:
                    summary["parsed_events"] += 1
    except OSError as error:
        summary["error"] = str(error)
        return summary

    summary["readable"] = True
    summary["formats"] = sorted(formats)

    if summary["parsed_events"] > 0:
        summary["rank"] = 0
    elif summary["sshd_lines"] > 0:
        summary["rank"] = 1

    return summary


def parse_listening_ports(tcp_content, tcp6_content=""):
    """Extrai portas TCP em escuta do formato de /proc/net/tcp."""
    ports = set()

    for content in (tcp_content, tcp6_content):
        for line in content.splitlines()[1:]:
            fields = line.split()

            if len(fields) < 4 or fields[3] != "0A":
                continue

            try:
                port = int(fields[1].rsplit(":", 1)[1], 16)
            except (IndexError, ValueError):
                continue

            ports.add(port)

    return ports


def local_listening_ports():
    try:
        tcp = Path("/proc/net/tcp").read_text(
            encoding="ascii",
            errors="replace",
        )
        tcp6_path = Path("/proc/net/tcp6")
        tcp6 = ""
        if tcp6_path.is_file():
            tcp6 = tcp6_path.read_text(
                encoding="ascii",
                errors="replace",
            )
    except OSError:
        return set(FALLBACK_PORTS)

    ports = parse_listening_ports(tcp, tcp6)

    if not ports:
        return set(FALLBACK_PORTS)

    return ports


def grab_ssh_banner(port, host="127.0.0.1", timeout=PROBE_TIMEOUT):
    """Conecta em localhost e devolve o banner, se for SSH."""
    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ) as connection:
            connection.settimeout(timeout)
            data = connection.recv(100)
    except OSError:
        return None

    banner = data.decode("latin-1", errors="replace").strip()

    if banner.startswith("SSH-"):
        return banner

    return None


def probe_ssh_service():
    ports = local_listening_ports()
    ssh_services = []

    for port in sorted(ports):
        banner = grab_ssh_banner(port)

        if banner is not None:
            ssh_services.append({"port": port, "banner": banner})

    return {
        "listening_ports": sorted(ports),
        "ssh_services": ssh_services,
    }


def discover(candidates=DEFAULT_AUTH_LOG_CANDIDATES, reference=None,
             probe_service=True):
    logs = []

    for candidate in candidates:
        summary = sniff_log(candidate, reference=reference)

        if summary["exists"]:
            logs.append(summary)

    ranked = [log for log in logs if log["rank"] is not None]
    best_log = None

    if ranked:
        ranked.sort(key=lambda log: (log["rank"], log["path"]))
        best_log = ranked[0]["path"]

    if probe_service:
        ssh = probe_ssh_service()
    else:
        ssh = {"listening_ports": [], "ssh_services": []}

    return {
        "logs": logs,
        "best_log": best_log,
        "ssh": ssh,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }


def format_report(report):
    lines = ["Descoberta de logs de autenticação:"]

    if not report["logs"]:
        lines.append("  Nenhum caminho conhecido encontrado.")
    else:
        for log in report["logs"]:
            if not log["readable"]:
                detail = log["error"] or "não legível"
                lines.append(f"  {log['path']} | {detail}")
                continue

            lines.append(
                f"  {log['path']} | {log['total_lines']} linhas, "
                f"{log['sshd_lines']} menções a sshd, "
                f"{log['parsed_events']} eventos reconhecidos"
            )

    if report["best_log"] is not None:
        lines.append(f"\nMelhor candidato: {report['best_log']}")
    else:
        lines.append("\nNenhum log com eventos SSH encontrado.")

    ssh = report["ssh"]
    lines.append("\nServiço SSH (localhost):")

    if ssh["ssh_services"]:
        for service in ssh["ssh_services"]:
            lines.append(
                f"  SSH na porta {service['port']}: "
                f"{service['banner']}"
            )
    else:
        lines.append("  Nenhum SSH escutando localmente.")

    if ssh["listening_ports"]:
        ports = ", ".join(
            str(port) for port in ssh["listening_ports"]
        )
        lines.append(f"  Portas TCP em escuta: {ports}")

    if report["best_log"] is None:
        lines.append(
            "\nDica: para logs do systemd, use "
            "'journalctl -u ssh | python analyzer.py --input -'."
        )

    return "\n".join(lines)


def config_path():
    base = os.environ.get("XDG_CONFIG_HOME")

    if base:
        return Path(base) / "auth-log-analyzer" / "config.json"

    return (
        Path.home() / ".config" / "auth-log-analyzer" / "config.json"
    )


def save_config(data, path=None):
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    try:
        os.chmod(target, 0o600)
    except OSError:
        pass


def load_config(path=None):
    target = path or config_path()

    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None

    if not isinstance(data, dict):
        return None

    if not isinstance(data.get("input"), str):
        return None

    return data


