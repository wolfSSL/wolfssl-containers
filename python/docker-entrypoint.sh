#!/bin/sh
set -e
trap 'echo wolfSSL startup test failed' ERR
python -c "import ssl; context = ssl.create_default_context()"
trap - ERR
"$@"
