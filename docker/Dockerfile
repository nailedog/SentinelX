# SentinelX Docker Environment - x86_64 Ubuntu
# Окружение для тестирования эксплойтов без защит

FROM --platform=linux/amd64 ubuntu:22.04

# Отключаем интерактивные запросы
ENV DEBIAN_FRONTEND=noninteractive

# Устанавливаем необходимые пакеты
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    python3 \
    python3-pip \
    gdb \
    strace \
    ltrace \
    file \
    binutils \
    vim \
    netcat \
    wget \
    ca-certificates \
    gpg \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем CMake 3.24+ из Kitware APT repository
RUN wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null \
    && echo 'deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ jammy main' | tee /etc/apt/sources.list.d/kitware.list >/dev/null \
    && apt-get update \
    && apt-get install -y cmake \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем pwntools для тестирования эксплойтов
RUN pip3 install pwntools

# Отключаем ASLR на уровне контейнера (требует --privileged)
# echo 0 > /proc/sys/kernel/randomize_va_space

# Создаем рабочую директорию
WORKDIR /sentinelx

# Копируем проект
COPY . /sentinelx/

# Устанавливаем права на выполнение
RUN chmod +x build.sh || true

# По умолчанию запускаем bash
CMD ["/bin/bash"]
