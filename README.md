# 🛡️ DNS Interception & RKN DPI Detector

> **Инструмент для проверки вмешательства ТСПУ (РКН) и провайдеров в DNS-трафик, тестирования доступности DoH (DNS-over-HTTPS) резолверов и детекции подмены IP-адресов прямо из браузера.**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Type](https://img.shields.io/badge/type-Single%20Page%20App-purple.svg)
![Platform](https://img.shields.io/badge/platform-GitHub%20Pages%20%7C%20Browser-success.svg)

---

## ⚡ О проекте

Веб-приложение создано для быстрой и наглядной проверки качества и безопасности DNS-соединения. Любой пользователь может открыть ссылку со своего смартфона или компьютера и за 5 секунд узнать:

1. **Слушает и фильтрует ли провайдер/ТСПУ DNS-запросы?**
2. **Работают ли защищенные протоколы DNS-over-HTTPS (DoH)**: Cloudflare, Google, Quad9, AdGuard, NextDNS, ControlD, Yandex, OpenDNS.
3. **Блокируются ли DoH резолверы на уровне TLS/SNI/IP** оборудованием ТСПУ.
4. **Подменяются ли IP-адреса на заглушки (Bogon IPs)**: `127.0.0.1`, `0.0.0.0`, `195.82.146.120` (заглушки Роскомнадзора).
5. **Определяется ли реальный IP, провайдер (ISP), ASN** и факт нахождения в зоне фильтрации РФ.

---

## 🚀 Как выкатить проект на свой GitHub Pages (Инструкция за 1 минуту)

Вы можете опубликовать эту страницу в своем GitHub аккаунте, чтобы ваши друзья и коллеги могли открывать ее по ссылке вида:
`https://<ваш-логин>.github.io/dns-interception-checker/`

### Шаг 1. Создайте новый репозиторий на GitHub
1. Перейдите на [github.com/new](https://github.com/new).
2. Укажите название репозитория: `dns-interception-checker` (или любое другое).
3. Выберите **Public** (Публичный) и нажмите **Create repository**.

### Шаг 2. Загрузите файлы в репозиторий
Выполните команды в терминале:

```bash
cd dns-interception-checker
git init
git add .
git commit -m "Initial commit: DNS Interception & RKN Detector"
git branch -M main
git remote add origin https://github.com/<ВАШ_GITHUB_ЛОГИН>/dns-interception-checker.git
git push -u origin main
```

*(Или просто перетащите файлы `index.html`, `check_dns_interception.py` и `README.md` через веб-интерфейс GitHub: `Add file` → `Upload files`)*.

### Шаг 3. Включите GitHub Pages
1. В вашем репозитории перейдите в **Settings** (Настройки) → **Pages** (в левой колонке).
2. В разделе **Build and deployment** / **Source** выберите **Deploy from a branch**.
3. В выпадающем списке веток выберите ветку `main` и папку `/(root)`.
4. Нажмите **Save**.
5. Через 30–60 секунд сайт будет доступен по ссылке:
   `https://<ВАШ_GITHUB_ЛОГИН>.github.io/dns-interception-checker/`

---

## 💻 Консольный компаньон (Полный тест сокетов UDP:53 / DoT:853)

Браузерные скрипты из соображений безопасности не могут формировать сырые UDP-сокеты на порт 53. Для проверки:
- **Флага AA (Authoritative Answer)** в NXDOMAIN от рекурсивных DNS;
- **Гонки пакетов (Packet Racing)** — мгновенная инъекция от ТСПУ против ответа настоящего DNS;
- **Перехвата фиктивных IP** (`192.0.2.53`);
- **DNS-over-TLS (DoT:853)**;

Запустите консольный скрипт одной командой:

```bash
# macOS / Linux / Termux:
curl -sSL https://raw.githubusercontent.com/<ВАШ_GITHUB_ЛОГИН>/dns-interception-checker/main/check_dns_interception.py | python3
```

Или локально:
```bash
python3 check_dns_interception.py
```

---

## 🧠 Сигнатуры и механики детекции

| Сигнатура | Механизм | Оценка опасности |
| :--- | :--- | :--- |
| **BOGON_REDIRECT** | Запрос возвращает IP-заглушку (`127.0.0.1`, `195.82.146.120`, `10.x.x.x`) | 🔴 Критическая (Прямая цензура) |
| **TSPU_DOH_BLOCKED** | DoH эндпоинт сбрасывается по TLS RST или таймауту на этапе Handshake | 🔴 Критическая (Блокировка DoH) |
| **SPOOFED_NXDOMAIN_AA** | Рекурсивный резолвер вернул флаг AA (Authoritative Answer) для чужого домена | 🔴 Критическая (Инъекция ТСПУ) |
| **PACKET_RACING** | Получено 2 разных ответа на 1 DNS-пакет (инъекция + оригинальный ответ) | 🔴 Критическая (Гонка ТСПУ) |
| **PORT53_HIJACKED** | Запрос на несуществующий IP `192.0.2.53` вернул ответ | 🔴 Критическая (Тотальный перехват порта 53) |
| **CLEAN** | Доступен DoH/DoT, резолвинг легитимен, задержка нормальная | 🟢 Безопасно |

---

## 🛠️ Как защитить свой DNS

1. **Включите DoH в браузере**:
   - *Chrome/Brave/Edge*: `Настройки` → `Конфиденциальность и безопасность` → `Безопасность` → `Использовать безопасный DNS-сервер` → Укажите свой DoH (AdGuard / NextDNS / Cloudflare).
   - *Firefox*: `Настройки` → `Приватность и защита` → `DNS поверх HTTPS` → `Максимальная защита`.
2. **Включите ECH (Encrypted Client Hello)**:
   - В Chrome: `chrome://flags/#encrypted-client-hello` → `Enabled`.
   - В Firefox включен автоматически при активации DoH.
3. **Используйте утилиты обхода DPI**:
   - **Zapret** / **GoodbyeDPI** / **ByeDPI** для обхода блокировок на уровне пакетов.
   - **Amnezia VPN / VLESS Reality** для полного шифрования трафика.

---

## 📄 Лицензия

Распространяется под свободной лицензией [MIT](LICENSE). Разрешено свободное использование, модификация и распространение.
