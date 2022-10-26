# Changelog

## [1.0] - September 2022

### Added
- DSG-5347 Added `create-csr` action to `certificate` subcommand
- DSG-5347 Added `--country` option to `certificate` subcommand
- DSG-4166 Added examples for manifest usage
- DSG-4412 Added ECC point conversion helper functions (ecc_conversions.py)
- DSG-5626 Added CLI -P argument to specify serial port, overriding auto-detection

### Changed
- DSG-5397 CLI `--skip-target-programming` option now has global scope only, and must be placed before subcommand
- DSG-5397 CLI `-v`/`--verbose` option now has global scope only, and must be placed before subcommand
- DSG-5397 CLI short form options now always use single-dash prefix (eg `-scac` instead of `--scac`)
- DSG-5446 Added metadata tag for Python 3.10
- DSG-5550 Removed metadata tag for Python 3.6
- DSG-5624 Updated pyedbglib dependency requirement for improved serial port detection

### Fixed
- DSG-4411 pytrustplatform reads command handler version instead of target firmware version

## [0.15.4] - December 2021

### Added
- DSG-2808 New ECC type detection
- DSG-2864 Configurable ORG name for certificate
- DSG-3978 Manifest utility
- DSG-4197 Sphinx documentation
- DSG-3979 Source release to GitHub

## [0.12.1] - April 2021

### Changed
- DSG-3307 Cosmetic changes for publication

## [0.12.0] - February 2021
- First public release to PyPi
