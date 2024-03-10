# certcloner

[![PyPI - Version](https://img.shields.io/pypi/v/certcloner.svg)](https://pypi.org/project/certcloner)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/certcloner.svg)](https://pypi.org/project/certcloner)

-----

So you need to create some test data for something that is signed with a certificate? Then you need to create your own certificate, preferably with a full chain, as similar to the original as possible. You could always fire up `step-ca` or something similar, but why not just clone the original chain, so that everything is as close to the real thing as possible?

Certcloner lets you do just that. Give it some certificates, and it will create clones with a private key that you control.

Limitations:

* Subject and Authority Key Identifiers will, by default, be updated, but stuff like SCT and CRL/AIA urls will not be.
* Only RSA and ECC keys are supported.

## Installation

You probably want to install this using `pipx`:

```console
pipx install certcloner
```

Or, you can install it with plain pip:

```console
pip install certcloner
```


## Usage

Just point certcloner to one or several files with certificates, in either PEM or DER format:

```console
certcloner ./mycert1.pem ./mycert2.crt ./mychain.pem
```

It will load all certificates, and output copies (plus the corresponding private key) to standard out.

Advanced usage:

```
Usage: certcloner [OPTIONS] [FILES]...

Options:
  --version               Show the version and exit.
  --no-comment            Do not include a comment in the finished certs.
  --keep-key-identifiers  Keep the original key identifiers in the finished
                          certs.
  -h, --help              Show this message and exit.
```

## License

`certcloner` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.
