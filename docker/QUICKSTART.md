# Quick Start Guide - Docker Exploitation Lab

## Prerequisite

Убедитесь что Docker установлен и запущен:
```bash
docker --version
docker ps
```

## Шаг 1: Запуск контейнера

```bash
# Из корневой директории SentinelX
cd docker

# Запуск через docker-compose (рекомендуется)
docker-compose up -d --build
docker-compose exec sentinelx /bin/bash

# Или напрямую через docker
docker build -t sentinelx -f Dockerfile ..
docker run -it --privileged --security-opt seccomp=unconfined \
    --name sentinelx-test sentinelx
```

## Шаг 2: Автоматическое тестирование

Внутри контейнера выполните:

```bash
# Запустить полный цикл сборки и тестирования
bash docker/build_and_test.sh
```

Этот скрипт автоматически:
- ✅ Отключит ASLR
- ✅ Скомпилирует уязвимую программу
- ✅ Соберет SentinelX
- ✅ Проанализирует бинарник
- ✅ Сгенерирует эксплойты
- ✅ Запустит тесты

## Шаг 3: Ручное тестирование (опционально)

```bash
# Компиляция
cd docker
gcc -m64 -fno-stack-protector -z execstack -no-pie \
    vuln_program.c -o vuln64

# Анализ
../build/SentinelX --binary vuln64

# Генерация эксплойтов
../build/SentinelX --binary vuln64 \
    --generate-exploits \
    --exploit-output exploits_x64

# Тестирование
python3 test_exploit.py
```

## Ожидаемый результат

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
$ exit

  ✓ EXPLOIT SUCCESSFUL!
[+] Successfully redirected execution to secret_backdoor()
```

## Что происходит?

1. **Buffer Overflow**: Отправляем > 64 байт в gets()
2. **Overwrite Return Address**: Перезаписываем адрес возврата
3. **Redirect Execution**: Указываем на secret_backdoor()
4. **Shell Access**: Получаем shell через system("/bin/sh")

## Troubleshooting

### ASLR не отключается
```bash
# Контейнер должен быть в privileged режиме
docker run -it --privileged ...
```

### Exploit не работает
```bash
# Проверьте адрес функции
nm docker/vuln64 | grep secret_backdoor

# Проверьте ASLR
cat /proc/sys/kernel/randomize_va_space  # Должно быть 0

# Проверьте защиты бинарника
readelf -l docker/vuln64 | grep GNU_STACK  # Должно быть RWE
```

## Очистка

```bash
# Остановить и удалить контейнер
docker-compose down

# Или через docker
docker stop sentinelx-test
docker rm sentinelx-test

# Удалить образ (опционально)
docker rmi sentinelx
```

## Что дальше?

Читайте полную документацию в `docker/README.md` для:
- Детального объяснения эксплуатации
- Ручного debugging через GDB
- Написания собственных эксплойтов
- Понимания shellcode
- Сравнения с защищенными системами
