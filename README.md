# Alikhan-Nessus-Splunk-Integration
Alikhan-Nessus-Splunk-Integration  это  автоматизированная интеграция между Tenable Nessus и Splunk, основанная на использовании (HEC)  Скрипт  получает результаты сканирования из Nessus (уязвимости, хосты, плагины) и отправляет их в Splunk для анализа, корреляции и построения дашбордов

Быстрый старт интеграции Nessus - Splunk
1. Клонируйте репозиторий:

git clone https://github.com/AlikhanKarabaevNEWPROJECT/Alikhan-Nessus-Splunk-Integration/

cd Alikhan-Nessus-Splunk-Integration

chmod +x nessus_splunk.py

chmod +x servers.json



2. Подготовьте данные для интеграции:
Nessus:

Access Key: <ваш_access_key>

Secret Key: <ваш_secret_key>

Splunk:

HEC Token: <ваш_HEC_token>

3. Установите переменные окружения

export HEC_TOKEN=<ваш_HEC_token>

export N_ACCESS_KEY=<ваш_access_key>

export N_SECRET_KEY=<ваш_secret_key>

4. Настройте файл servers.json с адресами ваших серверов Nessus и Splunk.

Замените "localhost"

6. Запустите скан в Nessus на интересующем хосте или сети.
7. Когда скан завершится (или если хотите остановить его вручную), выполните:

python3 nessus_splunk.py
