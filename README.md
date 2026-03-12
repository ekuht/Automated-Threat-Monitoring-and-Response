# Automated-Threat-Monitoring-and-Response


## Описание
Скрипт анализирует файл с alert-событиями, проверяет IP-адреса через VirusTotal API, получает информацию о CVE через Vulners API и отправляет уведомление в Telegram.

## Что делает скрипт
- читает alerts-файл;
- извлекает IP-адреса и сигнатуры;
- проверяет внешние IP через VirusTotal;
- получает данные о CVE через Vulners;
- формирует отчёт в CSV и JSON;
- строит график в PNG;
- отправляет уведомление в Telegram.

## Используемые технологии
- Python
- requests
- pandas
- matplotlib
- python-dotenv

## Файлы проекта
- `security_analysis.py` — основной скрипт
- `2024-11-26-traffic-analysis-exercise-alerts.txt` — входной файл с alert-событиями
- `output/report.csv` — отчёт
- `output/report.json` — отчёт в JSON
- `output/vulnerabilities.csv` — список CVE
- `output/top_alerted_ips.png` — график

## Настройка

Создать файл `.env` и указать в нём:
VT_API_KEY=
VULNERS_API_KEY=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
