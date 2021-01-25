#!/bin/bash

cargo criterion --features nightly

cargo doc
mv target/doc/* docs/doc

cp README.me docs/index.md
