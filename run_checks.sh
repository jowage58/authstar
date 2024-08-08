#!/usr/bin/env bash
set -xe

if [[ $1 == "clean" ]]; then
    echo "cleaning out .*cache/ directories"
    rm -rf .*cache/
fi

echo "CI is set to [${CI}]"
if [[ $CI != "true" ]]; then
    pre-commit run --all-files
fi

mypy --version
mypy

pytest
