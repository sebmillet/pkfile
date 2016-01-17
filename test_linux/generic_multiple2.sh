#!/bin/sh

PRG=../../src/pkfile

PRGARGS=$1
N=$2
TNAME=$3
INPUT=$4
OUTPUT=$5
REFERENCE=$6
SUFFIXE1=$7
SUFFIXE2=$8

F=0

REP=$(pwd | sed 's/.*\///')

i=1
while [ $i -le $N ]; do
	II="${INPUT}${i}${SUFFIXE1}"
	OO="${OUTPUT}${i}${SUFFIXE2}"
	RR="${REFERENCE}${i}${SUFFIXE2}"

# The sequence below ensures the stderr comes AFTER stdout, not
# in-between at an uncontrolled location.
	$PRG $PRGARGS -o tmpo.tmp $II > /dev/null 2>tmpe.tmp
	cat tmpo.tmp tmpe.tmp > $OO
	rm tmpo.tmp tmpe.tmp

	cmp $RR $OO > /dev/null 2>&1
	if [ "$?" -ne "0" ]; then
		F=1
	fi
	i=$(($i+1))
done

if [ $F -eq 1 ]; then
	if [ "$9" = "-batch" ]; then
		echo "$REP ** $TNAME: KO"
	fi
	exit 1;
else
	if [ "$9" = "-batch" ]; then
		echo "$REP    $TNAME: OK"
	fi
	exit 0;
fi
