FROM quay.io/pypa/manylinux2014_x86_64

ENV PATH /opt/python/cp38-cp38/bin:/opt/python/cp39-cp39/bin:/opt/python/cp310-cp310/bin:$PATH

ENV RUSTUP_HOME=/root/.rustup \
    CARGO_HOME=/root/.cargo \
    PATH=/root/.cargo/bin:$PATH

RUN curl --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly

WORKDIR /usr/src/pybulletproofs

COPY . .

RUN ./build-wheels.sh
