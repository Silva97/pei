#!/usr/bin/env bash

function run_tests() {
    make test name=pe_parse || exit
    make test name=pe_utils || exit
    make test name=pe_get_field || exit
}

time -p run_tests
