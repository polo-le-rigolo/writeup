#!/bin/bash
inputfile=$1
echo $inputfile
filesize=$(stat -c%s $inputfile)
echo $filesize
outsize=$((filesize - 13))
echo $outsize
dd if=$inputfile of=$inputfile.clean bs=1 skip=11 count=$outsize

