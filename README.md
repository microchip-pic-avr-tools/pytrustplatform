[![MCHP](images/microchip.png)](https://www.microchip.com)

# pytrustplatform
pytrustplatform is a collection of utilities for interacting with Microchip Trust Platform and
Microchip CryptoAuthentication™ devices

Install using pip from [pypi.org](https://pypi.org/project/pytrustplatform/):
```bash
pip install pytrustplatform
```

Browse source code on [github](https://github.com/microchip-pic-avr-tools/pytrustplatform)

Read API documentation on [github](https://microchip-pic-avr-tools.github.io/pytrustplatform)

Read the changelog on [github](https://github.com/microchip-pic-avr-tools/pytrustplatform/blob/main/CHANGELOG.md)

## Usage
pytrustplatform can be used as a command-line interface or a library

### Using the pytrust CLI
To get top level help
```bash
pytrust --help
```
To get help on specific command (in this example the `certificate` command)
```bash
pytrust certificate --help
```
To get the pytrustplatform version
```bash
pytrust --version
```

For more CLI usage examples see pypi.md

### Using pytrustplatform as a library package

To use pytrustplatform as a package it can be imported as:
```python
import pytrustplatform
```
To get help on the package as library:
```python
import pytrustplatform
help(pytrustplatform)
```

## Notes for Linux® systems
This package uses pyedbglib and other libraries for USB transport and some udev rules are required.  
For details see the pyedbglib package: https://pypi.org/project/pyedbglib
