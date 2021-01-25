#!/bin/bash

cargo criterion --features nightly
rm -rf pages/criterion/data

cargo doc
mv target/doc/ pages/doc
