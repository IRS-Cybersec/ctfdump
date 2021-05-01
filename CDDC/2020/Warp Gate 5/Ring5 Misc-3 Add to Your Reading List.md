# Ring 5: Misc-3 Add to your Reading List

331 Points  
GATE 5  
40 SOLVES  

## Description

As part of our resistance fighters' training program, we need to arm ourselves with academic knowledge. By the graces of my kind senior, he passed me some recommended reading materials.

One pdf seems to be annotated, while the other isn't. I wonder what is the difference between the two.. Can you spot it?

## Attached Files

Reading_Material.zip `c2218f912755a9a741ec169ddc4e47d4`

## How to solve

```sh
~$ diff <(lesspipe Educational\ Material.pdf) <(lesspipe Educational\ Material\ *)
36c36,37
<   14.     Provision of consent
---
>   14.     Provision of C
>                        consent
...
```
You eyeball the flag. Nothing else to say.

## Flag

This is left as an exercise to the reader. $\blacksquare$
