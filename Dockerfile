FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cmake -S . -B build -DSENTINELX_USE_LIEF=OFF -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build --config Release

ENTRYPOINT ["/app/build/SentinelX"]
CMD ["--help"]
