#!/bin/sh
set -e

apt-get update -y
apt-get install -y --no-install-recommends \
    bash \
    curl \
    git \
    procps \
    sudo
apt-get clean
rm -rf /var/lib/apt/lists/*
