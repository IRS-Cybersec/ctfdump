#!/bin/bash

#this script doesn't work for 100% of the executables, but it's enough to get 30 right answers in succession on a lucky try.
query() {
    gdb -batch -ex "file $1" -ex 'disassemble check' |
    grep -e movabs -e +93 -e +96 -e +99 |
    grep -Eo '(\$|-)0x[0-9a-z]*' |
    tr -d \$
}
f() {
    local resp="$(query "$1")";
    local hash="$(
        for l in `grep -o '^.........*$' <<< "$resp"`
        do  xxd -r -ps <<< "$(printf "%016x" "$l")" |
            rev |
            xxd -ps |
            tr -d \\n
        done
        )"
    (grep -v '^.........*$' <<< "$resp";echo "0x$hash";echo) |
    python3 -c 'c,b,a = tuple(map(lambda v: int(v,base=16), [input() for i in range(3)]));ls = int(input(),base=16).to_bytes(32,"big");print('"''"'.join(map(lambda v:chr(((v-a)^b)-c), ls)))'  #pretty
}
f "$1"
