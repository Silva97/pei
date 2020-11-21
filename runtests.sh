#!/usr/bin/env bash

function run_tests() {
    make test name=pe_parse || exit
    make test name=pe_utils || exit
}

time -p run_tests
