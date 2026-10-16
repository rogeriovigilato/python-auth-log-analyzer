import argparse
import csv
import ipaddress
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


AUTH_MESSAGE = (
    r"sshd\[\d+\]: "
    r"(?P<status>Failed|Accepted) (?:password|publickey) for "
    r"(?:invalid user )?"
    r"(?P<user>\S+) from "
    r"(?P<ip>\S+) port \d+ ssh2"
)

FORMATS = (
    (
        "iso",
        re.compile(
            r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
            r"(?:\.\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?) "
            r"\S+ " + AUTH_MESSAGE
        ),
    ),
    (
        "syslog",
        re.compile(
            r"(?P<timestamp>[A-Z][a-z]{2} {1,2}\d{1,2} "
            r"\d{2}:\d{2}:\d{2}) "
            r"\S+ " + AUTH_MESSAGE
        ),
    ),
)

ISO_TIMESTAMP_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
)

CSV_FIELDS = ["timestamp", "ip", "user", "status"]

CONTROL_CHARACTERS = re.compile(
    r"[\x00-\x1f\x7f-\x9f"
    r"\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]"
)

FORMULA_PREFIXES = ("=", "+", "-", "@")


class LogReadError(Exception):
    """Falha ao abrir ou ler a fonte de logs."""


def escape_character(character):
    code = ord(character)

    if code <= 0xFF:
        return f"\\x{code:02x}"

    return f"\\u{code:04x}"


def sanitize_text(value):
    """Escapa caracteres de controle e invisíveis."""
    return CONTROL_CHARACTERS.sub(
        lambda match: escape_character(match.group()),
        value,
    )


def sanitize_csv_value(value):
    """Neutraliza fórmulas e caracteres de controle no CSV."""
    value = sanitize_text(value)

    if value.startswith(FORMULA_PREFIXES):
        return "'" + value

    return value


def points_to_same_file(path_a, path_b):
    try:
        if path_a.samefile(path_b):
            return True
    except OSError:
        pass

    try:
        return path_a.resolve() == path_b.resolve()
    except (OSError, RuntimeError):
        return False


def read_log_lines(log_path):
    try:
        with log_path.open(encoding="utf-8") as log_file:
            for line in log_file:
                yield line.rstrip("\n")
    except (OSError, UnicodeError) as error:
        raise LogReadError(str(error)) from error


def read_stdin_lines():
    try:
        for line in sys.stdin:
            yield line.rstrip("\n")
    except (OSError, UnicodeError) as error:
        raise LogReadError(str(error)) from error


def positive_int(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "Informe um número inteiro maior que zero."
        )

    if number <= 0:
        raise argparse.ArgumentTypeError(
            "Informe um número inteiro maior que zero."
        )

    return number


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "Analisa logs SSH e identifica concentrações "
            "de falhas de autenticação por IP."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help=(
            "Caminho do arquivo de logs ('-' para ler da "
            "entrada padrão). Padrão: descoberta automática."
        ),
    )

    parser.add_argument(
        "--threshold",
        type=positive_int,
        default=5,
        help="Quantidade mínima de falhas para gerar um alerta.",
    )

    parser.add_argument(
        "--window-minutes",
        type=positive_int,
        default=10,
        help="Duração da janela de análise em minutos.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Caminho do CSV com todas as falhas reconhecidas.",
    )

    parser.add_argument(
        "--probe",
        action="store_true",
        help=(
            "Mostra a descoberta de logs e do serviço SSH "
            "e sai, sem analisar."
        ),
    )

    parser.add_argument(
        "--auto",
        action="store_true",
        help="Ignora a configuração salva e refaz a descoberta.",
    )

    return parser.parse_args()


def parse_iso_timestamp(text):
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    for timestamp_format in ISO_TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(text, timestamp_format)
        except ValueError:
            continue

        return parsed.replace(tzinfo=None)

    return None


def parse_syslog_timestamp(text, reference=None):
    base = reference or datetime.now()

    try:
        parsed = datetime.strptime(
            f"2000 {text}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None

    for year in (base.year, base.year - 1):
        try:
            candidate = parsed.replace(year=year)
        except ValueError:
            continue

        if candidate - base <= timedelta(days=1):
            return candidate

    return None


def match_line(line, reference=None):
    """Tenta reconhecer a linha e devolve (formato, evento)."""
    for name, pattern in FORMATS:
        match = pattern.fullmatch(line)

        if match is None:
            continue

        event = match.groupdict()

        if name == "iso":
            timestamp = parse_iso_timestamp(event["timestamp"])
        else:
            timestamp = parse_syslog_timestamp(
                event["timestamp"],
                reference=reference,
            )

        if timestamp is None:
            return None, None

        try:
            ipaddress.ip_address(event["ip"])
        except ValueError:
            return None, None

        event["timestamp"] = timestamp
        event["user"] = sanitize_text(event["user"])
        event["ip"] = sanitize_text(event["ip"])

        return name, event

    return None, None


def parse_line(line, reference=None):
    return match_line(line, reference=reference)[1]


def find_suspicious_window(events, threshold, window_minutes):
    ordered_events = sorted(
        events,
        key=lambda event: event["timestamp"],
    )

    window = timedelta(minutes=window_minutes)
    left = 0

    for right, current_event in enumerate(ordered_events):
        while (
            current_event["timestamp"]
            - ordered_events[left]["timestamp"]
            > window
        ):
            left += 1

        count = right - left + 1

        if count >= threshold:
            return ordered_events[left:right + 1]

    return []


class AlertTracker:
    """Mantém janelas recentes por IP e decide quando alertar."""

    def __init__(self, threshold, window_minutes):
        self.threshold = threshold
        self.window_minutes = window_minutes
        self.window = timedelta(minutes=window_minutes)
        self.events_by_ip = defaultdict(list)
        self.last_alert_start = {}

    def add_failure(self, event):
        events = self.events_by_ip[event["ip"]]
        events.append(event)
        self._prune(events, event["timestamp"])

        window_events = find_suspicious_window(
            events,
            threshold=self.threshold,
            window_minutes=self.window_minutes,
        )

        if not window_events:
            return None

        start = window_events[0]["timestamp"]
        previous = self.last_alert_start.get(event["ip"])

        if previous is not None and start - previous < self.window:
            return None

        self.last_alert_start[event["ip"]] = start

        return window_events

    def _prune(self, events, reference):
        while events and reference - events[0]["timestamp"] > self.window:
            events.pop(0)


class FailureCsvWriter:
    """Grava falhas no CSV conforme elas chegam."""

    def __init__(self, output_path):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = output_path.open(
            "w",
            newline="",
            encoding="utf-8",
        )
        self._writer = csv.DictWriter(
            self._file,
            fieldnames=CSV_FIELDS,
        )
        self._writer.writeheader()
        self._file.flush()

    def write(self, event):
        self._writer.writerow(
            {
                "timestamp": event["timestamp"].isoformat(),
                "ip": sanitize_csv_value(event["ip"]),
                "user": sanitize_csv_value(event["user"]),
                "status": event["status"],
            }
        )
        self._file.flush()

    def close(self):
        self._file.close()


def write_failures_csv(failures, output_path):
    writer = FailureCsvWriter(output_path)

    try:
        for event in failures:
            writer.write(event)
    finally:
        writer.close()


def print_alert(ip, window_events):
    users = sorted({event["user"] for event in window_events})
    start = window_events[0]["timestamp"]
    end = window_events[-1]["timestamp"]

    print("\nALERTA: padrão suspeito de falhas de autenticação")
    print(f"IP: {ip}")
    print(f"Falhas na janela detectada: {len(window_events)}")
    print(f"Usuários na janela: {', '.join(users)}")
    print(f"Início: {start.isoformat()}")
    print(f"Fim: {end.isoformat()}")


def print_statistics(
    total_lines,
    failures,
    successes,
    unrecognized,
    stats_by_ip,
    alert_count,
):
    print("\nResumo:")
    print(f"Total de linhas: {total_lines}")
    print(f"Falhas de autenticação: {failures}")
    print(f"Autenticações bem-sucedidas: {successes}")
    print(f"Linhas não reconhecidas: {unrecognized}")

    print("\nFalhas por IP:")

    if not stats_by_ip:
        print("Nenhuma falha de autenticação encontrada.")

    for ip, stats in sorted(stats_by_ip.items()):
        print(f"\nIP: {ip}")
        print(f"Quantidade de falhas: {stats['count']}")
        print(f"Usuários: {', '.join(sorted(stats['users']))}")
        print(f"Primeira falha: {stats['first'].isoformat()}")
        print(f"Última falha: {stats['last'].isoformat()}")

    print(f"\nTotal de IPs com alerta: {alert_count}")
    print("Observação: o alerta não confirma um ataque.")


def choose_input(force_discovery=False, reference=None):
    import discovery

    if not force_discovery:
        config = discovery.load_config()

        if config is not None:
            path = Path(config["input"]).expanduser()

            if path.is_file() and os.access(path, os.R_OK):
                return path, (
                    f"Log configurado: {path} "
                    f"(memorizado em {discovery.config_path()})"
                )

    report = discovery.discover(reference=reference)
    best = report["best_log"]

    if best is not None:
        summary = next(
            log for log in report["logs"] if log["path"] == best
        )
        discovery.save_config(
            {
                "input": best,
                "format": ", ".join(summary["formats"]),
                "ssh_services": report["ssh"]["ssh_services"],
                "discovered_at": datetime.now().isoformat(
                    timespec="seconds"
                ),
            }
        )

        return Path(best), (
            f"Log detectado automaticamente: {best} "
            f"(menções a sshd: {summary['sshd_lines']}, "
            f"eventos reconhecidos: {summary['parsed_events']})"
        )

    sample = Path(__file__).resolve().parent / "samples" / "auth.log"

    return sample, (
        "Nenhum log de autenticação com eventos SSH foi encontrado; "
        "usando o exemplo samples/auth.log."
    )


def record_failure(stats_by_ip, event):
    stats = stats_by_ip.get(event["ip"])
    timestamp = event["timestamp"]

    if stats is None:
        stats_by_ip[event["ip"]] = {
            "count": 1,
            "users": {event["user"]},
            "first": timestamp,
            "last": timestamp,
        }
        return

    stats["count"] += 1
    stats["users"].add(event["user"])
    stats["first"] = min(stats["first"], timestamp)
    stats["last"] = max(stats["last"], timestamp)


def main():
    args = parse_arguments()
    reference = datetime.now()

    if args.probe:
        import discovery

        report = discovery.discover(reference=reference)
        print(discovery.format_report(report))
        return 0

    use_stdin = False
    input_path = None

    if args.input is not None:
        if str(args.input) == "-":
            use_stdin = True
        else:
            input_path = args.input.expanduser()
    else:
        input_path, note = choose_input(
            force_discovery=args.auto,
            reference=reference,
        )
        print(note)

    output_path = None
    writer = None

    if args.output is not None:
        output_path = args.output.expanduser()

        if (
            input_path is not None
            and points_to_same_file(output_path, input_path)
        ):
            print(
                "Erro: o arquivo de saída não pode ser "
                "o mesmo arquivo de entrada."
            )
            return 1

        try:
            writer = FailureCsvWriter(output_path)
        except OSError as error:
            print(f"Erro ao gerar o CSV '{output_path}': {error}")
            return 1

    if use_stdin:
        print("Entrada: stdin (modo contínuo; Ctrl+C encerra)\n")
        source_label = "stdin"
    else:
        print(f"Arquivo analisado: {input_path}\n")
        source_label = str(input_path)

    print(
        f"Regra de alerta: pelo menos {args.threshold} falhas "
        f"do mesmo IP em uma janela de {args.window_minutes} "
        "minutos.\n"
    )

    tracker = AlertTracker(args.threshold, args.window_minutes)
    stats_by_ip = {}

    total_lines = 0
    failures = 0
    successes = 0
    unrecognized = 0
    alert_count = 0

    if use_stdin:
        lines = read_stdin_lines()
    else:
        lines = read_log_lines(input_path)

    try:
        for number, line in enumerate(lines, start=1):
            total_lines = number
            event = parse_line(line, reference=reference)

            if event is None:
                unrecognized += 1
                print(
                    f"Linha {number}: formato não reconhecido, "
                    "data ou IP inválidos"
                )
                continue

            if event["status"] == "Failed":
                failures += 1
                record_failure(stats_by_ip, event)

                if writer is not None:
                    try:
                        writer.write(event)
                    except OSError as error:
                        writer.close()
                        print(
                            "\nErro ao gerar o CSV "
                            f"'{output_path}': {error}"
                        )
                        return 1

                result = "FALHA"
            else:
                successes += 1
                result = "SUCESSO"

            print(
                f"{result} | "
                f"Horário: {event['timestamp'].isoformat()} | "
                f"Usuário: {event['user']} | "
                f"IP: {event['ip']}"
            )

            if event["status"] == "Failed":
                suspicious_events = tracker.add_failure(event)

                if suspicious_events:
                    alert_count += 1
                    print_alert(event["ip"], suspicious_events)
    except LogReadError as error:
        print(f"Erro ao ler '{source_label}': {error}")
        return 1
    except KeyboardInterrupt:
        print("\nLeitura interrompida pelo usuário (Ctrl+C).")
    except BrokenPipeError:
        return 0

    if writer is not None:
        writer.close()

    print_statistics(
        total_lines,
        failures,
        successes,
        unrecognized,
        stats_by_ip,
        alert_count,
    )

    if output_path is not None:
        print(f"\nCSV gerado: {output_path}")
        print(f"Linhas de falha exportadas: {failures}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
