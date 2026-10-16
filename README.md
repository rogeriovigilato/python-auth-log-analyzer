# python-auth-log-analyzer

> **Versão atual: 2.0** — descoberta automática de logs, múltiplos formatos e modo contínuo. As versões anteriores (1.5 e a publicação inicial) continuam disponíveis no histórico e nas releases antigas.

Ferramenta de linha de comando em Python para analisar logs de autenticação SSH e identificar concentrações de falhas de login por endereço IP.

Este projeto foi criado como um exercício prático de análise de logs e detecção de padrões suspeitos de autenticação. Ele não substitui um SIEM e não confirma ataques automaticamente.

## Objetivo

A ferramenta encontra logs de autenticação da máquina, identifica eventos de SSH e verifica se um mesmo endereço IP apresentou um número mínimo de falhas em uma janela de tempo configurável.

O resultado é um alerta de padrão suspeito, acompanhado de informações para investigação:

- IP de origem.
- Quantidade de falhas na janela.
- Usuários envolvidos.
- Horário de início e fim da janela detectada.
- Lista das falhas reconhecidas, exportável em CSV.

## Como funciona

A análise segue estas etapas:

1. Se nenhum `--input` for informado, procura logs de autenticação conhecidos da máquina e detecta o formato de cada um.
2. Verifica localmente se existe um serviço SSH escutando e em qual porta (banner `SSH-2.0-...`).
3. Reconhece linhas de login SSH (`Failed`/`Accepted`, `password`/`publickey`), validando data e endereço IP.
4. Agrupa as falhas por IP e mantém em memória apenas a janela recente.
5. Emite o alerta no momento em que um IP atinge o limite de falhas na janela.
6. Sanitiza usuário e IP antes de exibir no terminal e de exportar no CSV.

A regra padrão é:

```text
5 ou mais falhas do mesmo IP em uma janela de 10 minutos
```

Esses valores podem ser alterados pelos argumentos `--threshold` e `--window-minutes`.

## Formatos de log aceitos

| Formato | Exemplo de prefixo |
|---|---|
| ISO (segundos) | `2026-10-09T14:00:00 host sshd[1201]: Failed password ...` |
| ISO com fração e fuso | `2026-10-09T14:00:00.083014+00:00 host sshd[1201]: Failed password ...` |
| Syslog clássico | `Oct  9 14:00:00 host sshd[1201]: Failed password ...` |

No formato syslog clássico (sem ano), o ano é deduzido da data atual, com virada de ano tratada. O fuso horário não entra nos cálculos; a ferramenta usa a hora de parede registrada no log.

## Descoberta automática

Sem `--input`, a ferramenta:

1. Usa o log memorizado em `~/.config/auth-log-analyzer/config.json`, se ainda existir.
2. Senão, examina caminhos conhecidos (`/var/log/auth.log`, `/var/log/auth.log.1`, `/var/log/secure`, `/var/log/secure.1`) e escolhe o que tem eventos SSH reconhecíveis.
3. Verifica se há SSH escutando em localhost e em qual porta.
4. Se nada for encontrado, usa o exemplo embutido `samples/auth.log`.

Para ver o relatório da descoberta sem analisar:

```bash
python analyzer.py --probe
```

Para ignorar a configuração salva e refazer a descoberta:

```bash
python analyzer.py --auto
```

## Modo contínuo

`--input -` lê da entrada padrão, o que permite monitorar em tempo real:

```bash
journalctl -u ssh -f | python analyzer.py --input -
tail -f /var/log/auth.log | python analyzer.py --input -
```

Os alertas aparecem conforme as falhas chegam; Ctrl+C encerra e mostra o resumo.

## Como executar

Para analisar o log detectado automaticamente (ou o exemplo, se nada for encontrado):

```bash
python analyzer.py
```

Para informar um arquivo, um limite e uma janela de tempo:

```bash
python analyzer.py \
  --input samples/auth.log \
  --threshold 5 \
  --window-minutes 10
```

Há também um exemplo no formato real de syslog (`2026-10-14T20:00:12.183014-03:00 ...`):

```bash
python analyzer.py --input samples/auth-rsyslog.log
```

Para exportar todas as falhas reconhecidas em CSV:

```bash
python analyzer.py \
  --input samples/auth.log \
  --output reports/result.csv
```

O CSV contém as colunas `timestamp,ip,user,status` e é escrito conforme as falhas aparecem (compatível com o modo contínuo).

## Exemplo de saída

Com o arquivo de exemplo, a ferramenta identifica cinco falhas do IP `192.0.2.10` entre 14:00 e 14:04 e emite o alerta no momento em que a janela é atingida:

```text
FALHA | Horário: 2026-10-09T14:00:00 | Usuário: admin | IP: 192.0.2.10
FALHA | Horário: 2026-10-09T14:01:00 | Usuário: admin | IP: 192.0.2.10
FALHA | Horário: 2026-10-09T14:02:00 | Usuário: root | IP: 192.0.2.10
FALHA | Horário: 2026-10-09T14:03:00 | Usuário: root | IP: 192.0.2.10
FALHA | Horário: 2026-10-09T14:04:00 | Usuário: suporte | IP: 192.0.2.10

ALERTA: padrão suspeito de falhas de autenticação
IP: 192.0.2.10
Falhas na janela detectada: 5
Usuários na janela: admin, root, suporte
Início: 2026-10-09T14:00:00
Fim: 2026-10-09T14:04:00

Resumo:
Total de linhas: 8
Falhas de autenticação: 6
Autenticações bem-sucedidas: 1
Linhas não reconhecidas: 1
```

O alerta indica um padrão que merece investigação. Ele não afirma que houve um ataque.

## Requisitos

- Python 3.10 ou superior.
- Linux para a descoberta completa (leitura de `/proc` e caminhos clássicos). Em macOS e Windows, use `--input` com um arquivo.
- Nenhuma dependência externa.

O projeto usa apenas módulos da biblioteca padrão do Python.

## Preparar o ambiente

Na pasta do projeto, crie e ative um ambiente virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Não é necessário instalar pacotes adicionais.

## Executar os testes

Na pasta principal do projeto, execute:

```bash
python -m unittest discover -s tests -v
```

Os testes cobrem:

- Detecção de janela (limite, janela exata, eventos fora de ordem, lista vazia).
- Parser: data inválida, IP inválido, escape de caracteres de controle.
- Formatos: ISO com fração e fuso, syslog clássico com virada de ano, `publickey`.
- Alertas contínuos: limite, repetição só após a janela girar e memória limitada.
- CSV: neutralização de fórmulas, caracteres de controle e escrita incremental.
- Descoberta: ranking de logs, permissões, portas em escuta, banner SSH e configuração.

## Segurança

O conteúdo dos logs é tratado como entrada não confiável:

- Datas e endereços IP inválidos fazem a linha ser tratada como não reconhecida.
- Caracteres de controle e invisíveis (como sequências ANSI) são escapados antes de aparecer no terminal ou no CSV.
- Campos que começam com `=`, `+`, `-` ou `@` recebem o prefixo `'` no CSV, evitando injeção de fórmulas em planilhas.
- O log é lido em streaming, sem carregar o arquivo inteiro na memória.
- O arquivo de configuração fica em `~/.config/auth-log-analyzer/` com permissão restrita (`600`).
- A ferramenta recusa `--output` apontando para o mesmo arquivo de `--input`, inclusive via link simbólico.
- A sondagem de rede é apenas em localhost; a ferramenta não varre outras máquinas.

## Limitações

- Aceita apenas eventos de login do `sshd` (`password` e `publickey`).
- No formato syslog clássico, o ano é presumido a partir da data atual.
- A descoberta automática cobre caminhos clássicos do Linux; journald é acessado via `journalctl | --input -`.
- A detecção considera apenas falhas; não correlaciona eventos de outros tipos.
- Não há integração com SIEM, banco de dados ou notificações, nem bloqueio automático de IP.

## Próximas melhorias

- Descoberta em macOS e Windows (unified log e Event Log).
- Ação de bloqueio do IP no firewall (estilo fail2ban).
- Relatório em JSON.
- Correlação de falhas por usuário.

## Uso responsável

Use esta ferramenta apenas com logs que você tem permissão para analisar. Não utilize o projeto para acessar sistemas, contas ou redes de terceiros sem autorização explícita. A sondagem local embutida é limitada a esta máquina; ampliar a varredura para outros hosts exige autorização por escrito.
