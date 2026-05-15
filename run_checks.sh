#!/usr/bin/env bash
set -xe

export UV_FROZEN=1

uv run --active prek run --all-files
uv run --active ty check
uv run --active pytest
