#!/bin/bash

. venv/bin/activate

find ailib -type f -iname "*.py" -exec pycodestyle --ignore=E402,W504,E721,E722,E741 --max-line-length=120 {} +
find ailib -name '*.py' | codespell -f -
