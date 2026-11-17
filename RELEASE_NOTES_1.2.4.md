# TG WS Proxy Android 1.2.4 — сборочные заметки

> **Это просто рабочая обновлённая версия, которую собрал ИИ-агент.**
> Исходники открыты и соответствуют APK; гарантий и официальной поддержки нет.
> Сборка неофициальная, подписана собственным ключом.

Собрано из ветки `main` репозитория `amurcanov/tg-ws-proxy-android`
(коммит `540e588`) с переносом части изменений ядра `tg-ws-proxy` 1.11.4.

## Что изменено в ядре (Rust)

### Fake TLS (`src/faketls.rs`)
- Парсинг ClientHello: набор cipher suites и групп key_share.
- ServerHello теперь зеркалит клиента:
  - выбирается первый поддерживаемый TLS 1.3 suite из предложенных
    (0x1301 → 0x1303 → 0x1302);
  - при наличии группы `X25519MLKEM768` (0x11ec) отдаётся key_share
    этого размера (1088 байт «ciphertext» + 32 байта X25519), иначе X25519;
  - session_id копируется из ClientHello (0 или 32 байта) вместо
    фиксированных 32 нулей.
- Первая ApplicationData-запись — 64…160 байт (как fallback-профиль ядра)
  вместо 1900…2100 байт.
- Задержка перед ServerHello 8…24 мс (джиттер, как в ядре 1.11.4).

### CF worker pool (`src/proxy.rs`, `src/config.rs`)
- Реализован реальный фоновый refill: `schedule_refill` запускает задачу,
  которая создаёт недостающее соединение и снимает флаг `refilling`.
- Экспоненциальный backoff при неудачах: 1 с → 3600 с (лимит сдвига 12),
  состояние в `refill_failures`.
- Отмена задачи по `CancellationToken` не считается неудачей.
- `get()` не работает при `pool_size <= 0` или пустом списке CF-доменов.
- `reset()` очищает в том числе `refill_failures`.

## Версия
- `versionName = "1.2.4"`, `versionCode = 124`.

## Подпись
- `release.keystore` (RSA 2048, alias `tgwsproxy`, срок 10000 дней),
  параметры в `local.properties`.
- Включены v1/v2/v3 подписи.

## Окружение сборки
- Rust 1.100.0, host toolchain `stable-x86_64-pc-windows-gnu` (MSYS2 UCRT64).
- Android SDK 35/36, Build-Tools 35.0.0/36.0.0, NDK 27.2.12479018.
- JDK 21 (Temurin 21.0.13+9), Gradle 9.6.0, AGP 9.4.1.
