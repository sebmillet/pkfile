#!/bin/sh

# Execution of pkfile with all pem and der files found

PRG=../src/pkfile

find ../test_linux -regex ".*\.pem$\|.*\.der$" -exec valgrind --leak-check=full --show-leak-kinds=all ${PRG} --password abcde {} \;

