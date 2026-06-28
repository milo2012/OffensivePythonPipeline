FROM --platform=linux/amd64 debian:buster

RUN sed -i 's|http://deb.debian.org/debian|http://archive.debian.org/debian|g' /etc/apt/sources.list && \
    sed -i 's|http://security.debian.org/debian-security|http://archive.debian.org/debian-security|g' /etc/apt/sources.list && \
    sed -i '/buster-updates/d' /etc/apt/sources.list && \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check

RUN ldd --version | head -1 | grep -q '2.28' || (echo "WRONG GLIBC VERSION" && exit 1)

RUN apt-get update && apt-get install -y \
    build-essential wget curl git binutils \
    libssl-dev libffi-dev zlib1g-dev \
    libbz2-dev libreadline-dev libsqlite3-dev \
    liblzma-dev libncurses5-dev tk-dev \
    libpcap-dev \ 
    && rm -rf /var/lib/apt/lists/*

# Install Rust via rustup (needed for aardwolf dependency in NetExec)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustc --version && cargo --version

# Build Python 3.12 from source — required for certipy-ad 5.x, links against glibc 2.28
RUN wget -q https://www.python.org/ftp/python/3.12.7/Python-3.12.7.tgz && \
    tar xf Python-3.12.7.tgz && \
    cd Python-3.12.7 && \
    ./configure --enable-optimizations --enable-shared \
        --prefix=/usr/local \
        LDFLAGS="-Wl,-rpath=/usr/local/lib" && \
    make -j$(nproc) && \
    make altinstall && \
    cd / && rm -rf Python-3.12.7 Python-3.12.7.tgz

RUN python3.12 --version && \
    ldd /usr/local/bin/python3.12 | grep libc

RUN curl -sS https://bootstrap.pypa.io/pip/get-pip.py | python3.12

RUN python3.12 -m pip install --upgrade pip setuptools wheel && \
    python3.12 -m pip install flask pyinstaller packaging

RUN mkdir -p /builds

WORKDIR /app
COPY app.py /app/app.py
COPY templates/ /app/templates/

EXPOSE 5000
CMD ["python3.12", "app.py"]