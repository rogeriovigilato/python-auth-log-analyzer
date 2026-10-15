# python-auth-log-analyzer

Ferramenta de linha de comando em Python para analisar logs de autenticação SSH e identificar concentrações de falhas de login por endereço IP.

Este projeto foi criado como um exercício prático de análise de logs e detecção de padrões suspeitos de autenticação. Ele não substitui um SIEM e não confirma ataques automaticamente.

## Objetivo

A ferramenta lê um arquivo de log SSH, identifica eventos de autenticação e verifica se um mesmo endereço IP apresentou um número mínimo de falhas em uma janela de tempo configurável.

O resultado é um alerta de padrão suspeito, acompanhado de informações para investigação:

- IP de origem.
- Quantidade de falhas na janela.
- Usuários envolvidos.
- Horário de início e fim da janela detectada.
- Lista das falhas reconhecidas, exportável em CSV.

## Escopo

A primeira versão aceita apenas linhas de log SSH com este formato:

```text
2026-10-09T14:00:00 lab-linux sshd[1201]: Failed password for invalid user admin from 192.0.2.10 port 51001 ssh2
```

Também são aceitas falhas sem o texto `invalid user`, como:

```text
2026-10-09T14:02:00 lab-linux sshd[1203]: Failed password for root from 192.0.2.10 port 51003 ssh2
```

Eventos de autenticação bem-sucedida são identificados, mas não entram na contagem de falhas.

## Como funciona

A análise segue estas etapas:

1. Lê o arquivo informado em `--input`.
2. Reconhece eventos de autenticação SSH.
3. Separa falhas de autenticação de logins bem-sucedidos.
4. Agrupa as falhas por IP de origem.
5. Ordena os eventos por horário.
6. Verifica uma janela móvel de tempo.
7. Emite um alerta quando um IP atinge o limite de falhas na janela.

A regra padrão é:

```text
5 ou mais falhas do mesmo IP em uma janela de 10 minutos
```

Esses valores podem ser alterados pelos argumentos `--threshold` e `--window-minutes`.

## Requisitos

- Python 3.10 ou superior.
- Linux, macOS ou Windows.
- Nenhuma dependência externa.

O projeto usa apenas módulos da biblioteca padrão do Python.

## Preparar o ambiente

Na pasta do projeto, crie e ative um ambiente virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

No Windows PowerShell, use:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Não é necessário instalar pacotes adicionais.

## Como executar

Para analisar o arquivo de exemplo com a configuração padrão:

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

Para exportar todas as falhas reconhecidas em CSV:

```bash
python analyzer.py \
  --input samples/auth.log \
  --threshold 5 \
  --window-minutes 10 \
  --output reports/result.csv
```

O CSV contém as colunas:

```text
timestamp,ip,user,status
```

Ele inclui todas as falhas reconhecidas, inclusive aquelas de IPs que não atingiram o limite de alerta.

## Exemplo de saída

Com o arquivo de exemplo, a ferramenta identifica cinco falhas do IP `192.0.2.10` entre 14:00 e 14:04:

```text
ALERTA: padrão suspeito de falhas de autenticação
IP: 192.0.2.10
Falhas na janela detectada: 5
Usuários na janela: admin, root, suporte
Início: 2026-10-09T14:00:00
Fim: 2026-10-09T14:04:00
```

O alerta indica um padrão que merece investigação. Ele não afirma que houve um ataque.

## Executar os testes

Na pasta principal do projeto, execute:

```bash
python -m unittest discover -s tests -v
```

Os testes verificam a função de detecção de janela em cenários como:

- Cinco falhas dentro da janela.
- Falhas espaçadas fora da janela.
- Apenas quatro falhas.
- Cinco falhas abrangendo exatamente dez minutos.
- Eventos recebidos fora de ordem.
- Janela que descarta eventos antigos.
- Lista vazia.

## Limitações

- A ferramenta analisa apenas o formato de log SSH definido nesta primeira versão.
- Não valida se o IP extraído é um endereço IP válido.
- A detecção considera apenas falhas; não correlaciona eventos de outros tipos.
- O alerta é baseado em contagem e janela de tempo, sem inteligência adicional.
- Não há integração com SIEM, banco de dados ou notificações.
- A exportação CSV não é coberta por testes automatizados nesta versão.

## Próximas melhorias

- Suporte a outros formatos de log.
- Validação do endereço IP.
- Testes para o parser e para a exportação CSV.
- Relatório em JSON.
- Correlação de falhas por usuário.
- Integração futura com um laboratório de SOC.

## Uso responsável

Use esta ferramenta apenas com logs que você tem permissão para analisar. Não utilize o projeto para acessar sistemas, contas ou redes de terceiros sem autorização explícita.
