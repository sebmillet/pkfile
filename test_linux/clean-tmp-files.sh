#!/bin/sh

find -regex ".*/[tu][0-9][0-9]/tmp[^.]+.der$" | while read f; do rm "$f"; done
find -regex ".*/[tu][0-9][0-9]/tmp[^.]+.bin$" | while read f; do rm "$f"; done
find -regex ".*/[tu][0-9][0-9]/tmp[^.]+.txt$" | while read f; do rm "$f"; done
