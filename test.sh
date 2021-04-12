#!/usr/bin/env bash

set -e

function run_tests() {
    make test name=pe_parse
    make test name=pe_utils
    make test name=pe_get_field
    make test name=pe_set_field
    make test name=choose

    # Note: pe_write test doesn't works on Travis CI.
    # make test name=pe_write
}

time -p run_tests
exit 0
