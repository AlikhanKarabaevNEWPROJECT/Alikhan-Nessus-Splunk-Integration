# Alikhan-Nessus-Splunk-Integration

**Alikhan-Nessus-Splunk-Integration** — это автоматизированная интеграция между **Tenable Nessus** и **Splunk**, основанная на использовании **HEC (HTTP Event Collector)**. Скрипт получает результаты сканирования из Nessus (**уязвимости, хосты, плагины**) и отправляет их в Splunk для **анализа, корреляции и построения дашбордов**.

**Быстрый старт интеграции Nessus ↔ Splunk**

**Клонируйте репозиторий:**  
`git clone https://github.com/AlikhanKarabaevNEWPROJECT/Alikhan-Nessus-Splunk-Integration/`  
`cd Alikhan-Nessus-Splunk-Integration`  
`chmod +x nessus_splunk.py`  
`chmod +x servers.json`

**Подготовьте данные для интеграции:**  

**Nessus:**  
- **Access Key:** `<ваш_access_key>`  
- **Secret Key:** `<ваш_secret_key>`  

**Splunk:**  
- **HEC Token:** `<ваш_HEC_token>`

**Установите переменные окружения:**  
`export HEC_TOKEN=<ваш_HEC_token>`  
`export N_ACCESS_KEY=<ваш_access_key>`  
`export N_SECRET_KEY=<ваш_secret_key>`

**Настройте файл `servers.json`** с адресами ваших серверов Nessus и Splunk. Замените `"localhost"` на реальные IP

**Запустите скан в Nessus** на интересующем хосте или сети. Когда скан завершится (или если хотите остановить его вручную), выполните:  
`python3 nessus_splunk.py`

**Готово!** Результаты сканирования будут отправлены в Splunk и доступны для **анализа и построения дашбордов**.
