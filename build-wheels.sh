#!/bin/bash

# Based on:
#
# * https://github.com/nanoporetech/fast-ctc-decode/blob/master/.github/workflows/build-wheels.sh
# * https://github.com/konstin/complex-manylinux-maturin-docker/blob/main/.github/workflows/build.yml

set -e -x

for PYBIN in /opt/python/cp3[891]*/bin; do
    "${PYBIN}/pip" install maturin
    "${PYBIN}/maturin" build --interpreter "${PYBIN}/python" --release --manylinux 2014
done
