# scanner-external-go

Внешний воркер для Scanner. Полит задачи с управляющего сервера (Laravel), выполняет их и отправляет результаты обратно.

## Поддерживаемые типы задач

| Тип | Описание |
|-----|---------|
| `check_ips` | TCP порт-скан по списку IP и портов |
| `execute_command` | Выполнение shell-команды на воркере |
| `internetdb` | Обогащение IP через [internetdb.shodan.io](https://internetdb.shodan.io) (бесплатно, без ключа) |

## Конфигурация

Скопировать `.env.example` → `.env` и заполнить:

```env
SCANNER_API_URL=https://your-scanner-domain.com   # URL управляющего сервера
SCANNER_UNIQUE_ID=my-worker-01                    # Уникальный ID воркера (uuid или любая строка)
SCANNER_AUTH_TOKEN=secret-token                   # Токен авторизации (совпадает с сервером)
SCANNER_LIMIT=10                                  # Сколько задач брать за один запрос
```

## Запуск

### Локально / разработка

```bash
# Установить зависимости
go mod download

# Запустить без сборки
make run

# Или собрать бинарник и запустить
make build
./bin/scanner
```

### Продакшн (systemd / supervisor)

Собрать и перезапустить через `deploy.sh`:

```bash
./deploy.sh
```

Скрипт выполняет: `git pull` → `go build` → `supervisorctl restart scanner-go`.

Пример конфига supervisor (`/etc/supervisor/conf.d/scanner-go.conf`):

```ini
[program:scanner-go]
command=/path/to/scanner-external-go/scanner
directory=/path/to/scanner-external-go
autostart=true
autorestart=true
user=www-data
stdout_logfile=/var/log/scanner-go.log
stderr_logfile=/var/log/scanner-go-error.log
environment=HOME="/var/www"
```

После добавления конфига:

```bash
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start scanner-go
```

## Как работает

1. Каждые N секунд (задаётся сервером через `poll_interval`) воркер шлёт `GET /api/external-jobs`
2. Сервер отдаёт задачи, чей тип входит в `supported-job-types` заголовок запроса
3. Воркер обрабатывает задачи и отправляет результаты через `POST /api/external-jobs`

### InternetDB (`internetdb`)

- Параллельные запросы к `https://internetdb.shodan.io/{ip}` — **20 горутин** одновременно
- Таймаут на запрос: **5 секунд**
- ~1000 IP обрабатываются за 10–30 секунд
- Возвращает: `ports`, `hostnames`, `tags`, `vulns`, `cpes`, флаги `not_found` / `fetch_error`

### Port scan (`check_ips`)

- TCP connect по каждому `ip:port`, параллельно по всем IP для каждого порта
- Пытается сделать HTTP GET и парсит статус-код из ответа
- Таймаут задаётся в payload задачи

### Execute command (`execute_command`)

- Выполняет произвольную команду через `bash -c`
- Поддерживает `working_dir`, `env`, `timeout`
- Есть базовая защита от опасных паттернов (`rm -rf /`, fork bomb и т.п.)

## Версия

Текущая версия: `0.3.1` (задаётся в `internal/config/config.go`)
