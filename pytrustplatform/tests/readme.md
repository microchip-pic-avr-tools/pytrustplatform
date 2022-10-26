This folder contains tests based on Python unittest. Tests are run from the root of the repo (pytrustplatform not pytrustplatform/pytrustplatform or pytrustplatform/pytrustplatform/tests)

To run all tests:
~~~~
\pytrustplatform>pytest
~~~~

To run a specific tests use the -k option of pytest to use a substring expression to mask tests.
For example to run all tests in test_cli_certificate.py:
~~~~
\pytrustplatform>pytest -k test_cli_certificate
~~~~
To run a specific test:
~~~~
\pytrustplatform>pytest -k test_get_skid_cert_alias
~~~~

To get logging output when running tests use the --log-cli-level option.
For example to turn on INFO level logging:
~~~~
\pytrustplatform>pytest --log-cli-level INFO
~~~~
