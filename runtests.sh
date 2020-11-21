#!/usr/bin/env bash

function run_tests() {
    make test name=pe_parse || exit
}

time -p run_tests
