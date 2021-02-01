#!/bin/bash

cargo criterion --features nightly

cargo doc
mv -f target/doc/* docs/doc

cp README.md docs/index.md
