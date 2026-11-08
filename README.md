# Учебный UDP-обмен

Сборка (C++17, `-Wall -Wextra -Werror`):

```sh
cmake -S . -B build
cmake --build build
```

В первом терминале запустите сервер: `./build/server 127.0.0.1 0` — последний аргумент `0` выбирает свободный порт. В другом терминале передайте напечатанный порт клиенту: `./build/client 127.0.0.1 54321`. Клиент отправляет каждое сообщение один раз; при отсутствии ответа завершает попытку через 5 секунд.

Пример успешного вывода (порт и ID будут другими):

```text
# сервер
listening 127.0.0.1:54321
ok exchange=42
# клиент
ok exchange=42
```

Сервер обрабатывает одну активную попытку в течение 5 секунд, привязанную к `exchange_id` и адресу отправителя. Клиент принимает ответы только с указанного адреса сервера.

Промежуточные криптографические данные и данные сессии очищаются функцией `secure_zero` из `src/secure_zero.c`. Запись идёт через `volatile unsigned char*`, поэтому компилятор не может убрать её как ненужную.

## SHA-256

В `third_party/sha256.c` и `third_party/sha256.h` лежат неизменённые исходники SHA-256 Брэда Конте из проекта [crypto-algorithms](https://github.com/B-Con/crypto-algorithms): [sha256.c](https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c), [sha256.h](https://github.com/B-Con/crypto-algorithms/blob/master/sha256.h). Автор распространяет код как [общественное достояние](https://github.com/B-Con/crypto-algorithms#about).

API исходника: `sha256_init(SHA256_CTX*)` инициализирует состояние; `sha256_update(SHA256_CTX*, const BYTE*, size_t)` добавляет байты; `sha256_final(SHA256_CTX*, BYTE*)` записывает 32 байта хеша.

В `cryptography.hpp/.cpp` определены `Calculate_secret(TotalPayload)` и `Calculate_hmac(secret, type, TotalPayload)`. HMAC-SHA256 реализован поверх SHA-256 по схеме `SHA256((key ⊕ opad) || SHA256((key ⊕ ipad) || message))`, где размер блока — 64 байта, `ipad = 0x36`, `opad = 0x5c`.

Порядок байтов для секрета: `client_random || server_random || nonce || exchange_id`. Для HMAC: `type || exchange_id || client_random || server_random || nonce`. `exchange_id` в обоих случаях записывается четырьмя байтами в network order (старший байт первым), независимо от порядка полей `TotalPayload`.
