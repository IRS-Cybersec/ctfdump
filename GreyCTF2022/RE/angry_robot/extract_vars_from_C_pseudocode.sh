lol() {
  grep 'a2 \* a1 % [0-9]* + a1 + a2' -o "$1" | grep -o ' [0-9]* ' | tr -d \ 
  grep qmemcpy "$1" | grep -o '".*"' | tr -d \"
  grep 'i <= [0-9]*' -o "$1" | grep -o '[0-9]*'
}

for f in *.c
do lol "$f" > "$f.vars"
done
