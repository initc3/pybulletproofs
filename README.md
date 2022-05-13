# Bulletproofs in Python
[![PyPI version](https://badge.fury.io/py/pybulletproofs.svg)](https://badge.fury.io/py/pybulletproofs)
![PyPI - Format](https://img.shields.io/pypi/format/pybulletproofs)
![PyPI - Status](https://img.shields.io/pypi/status/pybulletproofs)

**WARNING**: Work-in-progress. Only meant for experimental purposes.

---

We use pyo3 to wrap the [bulletproof implementation by dalek-cryptography][bulletproofs]
in python.

## Quickstart
Install latest development version from PyPI.

```bash
pip install pybulletproofs
```

To test the python library, run the following proof and verification.

```bash
from pybulletproofs import zkrp_prove, zkrp_verify

proof1, comm1, _ = zkrp_prove(2022, 32)
proof2, comm2, _ = zkrp_prove(2023, 32)

assert zkrp_verify(proof1, comm1)
assert !zkrp_verify(proof2, comm1)
```

## Development

### Dependencies
- Python 3.8 and up
- Rust 1.62.0-nightly (60e50fc1c 2022-04-04) and up

### Building
We first create a python virtual environment, activate it, and install
[`maturin`][maturin] into the virtual environment.

```bash
$ python -m venv .env
$ source .env/bin/activate
$ pip install maturin
```

To compile the Rust implementation into a python library, run the following code snippet.

```bash
$ maturin init
$ maturin develop
```

Alternatively, use the [Dockerfile][dockerfile].


[bulletproofs]: https://github.com/dalek-cryptography/bulletproofs/blob/main/README.md
[dockerfile]: https://github.com/initc3/pybulletproofs/blob/main/Dockerfile
[maturin]: https://github.com/PyO3/maturin
