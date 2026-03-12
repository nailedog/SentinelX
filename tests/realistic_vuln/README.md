# Реалистичный пример уязвимости - Simple Authentication Server

Демонстрация обнаружения и эксплуатации реальной уязвимости переполнения буфера.

## Описание

`simple_auth.c` - упрощенная имитация сервера аутентификации с классической уязвимостью strcpy().

**Уязвимость:**
```c
int process_login(const char* user_input) {
    char username[32];  // Буфер на стеке
    strcpy(username, user_input);  // Нет проверки длины!
    ...
}
```

## Сборка

```bash
cd tests/realistic_vuln
gcc -fno-stack-protector -Wno-deprecated-declarations simple_auth.c -o simple_auth
```

## Тестирование уязвимости

### Нормальная работа
```bash
./simple_auth admin
# [+] Authentication successful!
```

### Переполнение буфера
```bash
./simple_auth $(python3 -c "print('A'*100)")
# Segmentation fault (код возврата -5)
```

## Анализ через SentinelX

### 1. Анализ исходного кода
```bash
../../build/SentinelX --source simple_auth.c
```

**Обнаружено:**
- `[CRITICAL][CERTAIN] SRC_UNSAFE_CALL_strcpy` в строке 38
- Рекомендация: использовать strncpy() или strlcpy()

### 2. Анализ бинарного файла
```bash
../../build/SentinelX --binary simple_auth
```

**Обнаружено:**
- `[WARNING][MEDIUM] BIN_UNSAFE_CALL_strcpy` в функции `_process_login`
- Показан дизассемблированный код с контекстом
- Offset: 0x1000005b4, return address: 0x1000005b8

### 3. Генерация эксплойтов
```bash
../../build/SentinelX --binary simple_auth \
    --generate-exploits \
    --exploit-format both \
    --exploit-output exploits
```

**Сгенерировано:**
- `exploit_BIN_UNSAFE_CALL_strcpy__process_login.py` - Python (pwntools)
- `exploit_BIN_UNSAFE_CALL_strcpy__process_login.c` - C версия

## Структура эксплойта

Сгенерированный эксплойт содержит:

1. **Shellcode** (32 байта)
   ```
   ARM64 shellcode: execve("/bin/sh", NULL, NULL)
   ```

2. **Padding** (120 байт)
   ```
   Заполнение 'A' до return address
   ```

3. **Return address** (8 байт для ARM64)
   ```
   Адрес shellcode или ROP gadget
   ```

## Автоматизированное тестирование

```bash
python3 test_exploit.py
```

**Результаты:**
- ✅ Нормальный ввод работает
- ✅ Переполнение вызывает crash (return code -5)
- ✅ Уязвимость подтверждена
- ⚠️  Полная эксплуатация блокируется защитами macOS

## Защиты в современных системах

Почему эксплойт не работает полностью на macOS:

1. **Stack Canary** - детектирует перезапись стека
2. **NX/DEP** - стек не исполняемый (shellcode не запустится)
3. **ASLR** - адреса рандомизированы
4. **Code Signing** - проверка подписи кода

## Как работала бы эксплуатация без защит

1. Отправить payload длиной > 32 байта
2. Перезаписать буфер `username[32]`
3. Перезаписать saved frame pointer
4. **Перезаписать return address** → адрес shellcode
5. Функция возвращается → переход на shellcode
6. Shellcode выполняет `execve("/bin/sh")`
7. Атакующий получает shell

## Как исправить уязвимость

```c
// ДО (уязвимо)
strcpy(username, user_input);

// ПОСЛЕ (безопасно)
strncpy(username, user_input, sizeof(username) - 1);
username[sizeof(username) - 1] = '\0';

// или лучше
strlcpy(username, user_input, sizeof(username));
```

## Выводы

1. ✅ **SentinelX обнаружил** уязвимость в исходниках и бинарнике
2. ✅ **Эксплойт сгенерирован** автоматически с правильным shellcode
3. ✅ **Переполнение подтверждено** тестами (crash при вводе > 32 байт)
4. ℹ️  **Современные защиты** предотвращают полную эксплуатацию
5. 📚 **Образовательная ценность** - демонстрация классической уязвимости

## Дополнительно

**Адрес функции secret_function:**
```bash
nm simple_auth | grep secret_function
# 0000000100000644 T _secret_function
```

Эта функция никогда не вызывается в нормальном потоке выполнения, но при переполнении можно перезаписать return address на её адрес, демонстрируя контроль над выполнением.
