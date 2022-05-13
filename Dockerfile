FROM python:3.10.4-bullseye

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

COPY --from=rustlang/rust:nightly-bullseye /usr/local/cargo /usr/local/cargo
COPY --from=rustlang/rust:nightly-bullseye /usr/local/rustup /usr/local/rustup

WORKDIR /usr/src/pybulletproofs

COPY . .

RUN pip install maturin ipython

RUN maturin develop
