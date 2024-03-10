# certcloner

[![PyPI - Version](https://img.shields.io/pypi/v/certcloner.svg)](https://pypi.org/project/certcloner)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/certcloner.svg)](https://pypi.org/project/certcloner)

-----

So you need to create some test data for something that is signed with a certificate? So you need to whip up your own certificate, preferably with a full chain, to be as similar to the original as possible. You could always fire up `step-ca` or something similar, but why not just clone the original chain, so that everything is as close to the real thing as possible?

Certcloner lets you do just that. Give it a some certificates, and it will create clones with a private key that you control.

Limitations:

* Subject and Authority Key Identifiers will, by default, be updated, but stuff like SCT and CRL/AIA urls will not be.
* Only RSA and ECC keys are supported.

**Table of Contents**

- [Installation](#installation)
- [License](#license)

## Installation

```console
pip install certcloner
```

## License

`certcloner` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.
