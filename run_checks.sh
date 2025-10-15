#!/usr/bin/env bash
set -xe

if [[ $1 == "clean" ]]; then
    echo "cleaning out .*cache/ directories"
    rm -rf .*cache/
fi

if [[ -d .venv/bin ]]; then
    export PATH=.venv/bin:$PATH
fi

echo "CI is set to [${CI}]"
if [[ $CI != "true" ]]; then
    pre-commit run --all-files
fi

mypy --version
mypy

ty --version
ty check

pytest
