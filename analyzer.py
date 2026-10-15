import argparse
import csv
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


LOG_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}) "
    r"\S+ sshd\[\d+\]: "
    r"(?P<status>Failed|Accepted) password for "
    r"(?:invalid user )?"
    r"(?P<user>\S+) from "
    r"(?P<ip>\S+) port \d+ ssh2"
)

CSV_FIELDS = ["timestamp", "ip", "user", "status"]


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
    default_input = (
        Path(__file__).resolve().parent / "samples" / "auth.log"
    )

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
        default=default_input,
        help="Caminho do arquivo de logs.",
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

    return parser.parse_args()


def parse_line(line):
    match = LOG_PATTERN.fullmatch(line)

    if match is None:
        return None

    event = match.groupdict()

    try:
        event["timestamp"] = datetime.fromisoformat(event["timestamp"])
    except ValueError:
        return None

    return event


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


def write_failures_csv(failures, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=CSV_FIELDS,
        )

        writer.writeheader()

        for event in failures:
            writer.writerow(
                {
                    "timestamp": event["timestamp"].isoformat(),
                    "ip": event["ip"],
                    "user": event["user"],
                    "status": event["status"],
                }
            )


def main():
    args = parse_arguments()
    log_path = args.input.expanduser()

    output_path = None

    if args.output is not None:
        output_path = args.output.expanduser()

        if output_path.resolve() == log_path.resolve():
            print(
                "Erro: o arquivo de saída não pode ser "
                "o mesmo arquivo de entrada."
            )
            return 1

    try:
        content = log_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        print(f"Erro ao ler '{log_path}': {error}")
        return 1

    lines = content.splitlines()

    failures = 0
    successes = 0
    unrecognized = 0

    failures_by_ip = defaultdict(list)
    all_failures = []

    print(f"Arquivo analisado: {log_path}\n")

    for number, line in enumerate(lines, start=1):
        event = parse_line(line)

        if event is None:
            unrecognized += 1
            print(
                f"Linha {number}: "
                "formato não reconhecido ou data inválida"
            )
            continue

        if event["status"] == "Failed":
            failures += 1
            failures_by_ip[event["ip"]].append(event)
            all_failures.append(event)
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

    print("\nResumo:")
    print(f"Total de linhas: {len(lines)}")
    print(f"Falhas de autenticação: {failures}")
    print(f"Autenticações bem-sucedidas: {successes}")
    print(f"Linhas não reconhecidas: {unrecognized}")

    print("\nFalhas por IP:")

    if not failures_by_ip:
        print("Nenhuma falha de autenticação encontrada.")

    for ip, events in sorted(failures_by_ip.items()):
        users = sorted({event["user"] for event in events})
        first_seen = min(event["timestamp"] for event in events)
        last_seen = max(event["timestamp"] for event in events)

        print(f"\nIP: {ip}")
        print(f"Quantidade de falhas: {len(events)}")
        print(f"Usuários: {', '.join(users)}")
        print(f"Primeira falha: {first_seen.isoformat()}")
        print(f"Última falha: {last_seen.isoformat()}")

    print("\nAnálise de padrões suspeitos:")
    print(
        f"Regra: pelo menos {args.threshold} falhas do mesmo IP "
        f"em uma janela de {args.window_minutes} minutos."
    )

    alert_count = 0

    for ip, events in sorted(failures_by_ip.items()):
        suspicious_events = find_suspicious_window(
            events,
            threshold=args.threshold,
            window_minutes=args.window_minutes,
        )

        if not suspicious_events:
            print(
                f"\nIP: {ip} | "
                "Não atingiu o limite na janela definida."
            )
            continue

        alert_count += 1

        users = sorted(
            {event["user"] for event in suspicious_events}
        )

        start = suspicious_events[0]["timestamp"]
        end = suspicious_events[-1]["timestamp"]

        print("\nALERTA: padrão suspeito de falhas de autenticação")
        print(f"IP: {ip}")
        print(f"Falhas na janela detectada: {len(suspicious_events)}")
        print(f"Usuários na janela: {', '.join(users)}")
        print(f"Início: {start.isoformat()}")
        print(f"Fim: {end.isoformat()}")

    print(f"\nTotal de IPs com alerta: {alert_count}")
    print("Observação: o alerta não confirma um ataque.")

    if output_path is not None:
        try:
            write_failures_csv(all_failures, output_path)
        except (OSError, UnicodeError) as error:
            print(f"\nErro ao gerar o CSV '{output_path}': {error}")
            return 1

        print(f"\nCSV gerado: {output_path}")
        print(f"Linhas de falha exportadas: {len(all_failures)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
