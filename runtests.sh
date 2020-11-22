#!/usr/bin/env bash

function run_tests() {
    make test name=pe_parse || exit
    make test name=pe_utils || exit
    make test name=pe_get_field || exit
    make test name=pe_set_field || exit
    make test name=pe_write || exit
}

time -p run_tests
exit 0
