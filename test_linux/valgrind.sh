#!/bin/sh

# Execution of pkfile on pem files found under test_linux

PRG=../src/pkfile

find -name "*.pem" -exec valgrind --leak-check=full --show-leak-kinds=all ${PRG} --password pwd1 {} \;
