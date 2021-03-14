def is_prime(n):
    # Implement some prime checking function here
    return True  # Placeholder

def bti(s):
    out = 0
    for i in s:
        out = (out * 256) + ord(i)
    return out

def encrypt():
    fp = open('params.txt', 'r')
    p = int(fp.readline())
    q = int(fp.readline())

    assert is_prime(p)
    assert is_prime(q)

    n = p**q
    e = 1000000000000000003

    assert (p-1) % e != 0

    fc = open('flag.txt', 'r')
    m = bti(fc.read())

    if (m > n):
        print("PANIC")
        return

    c = pow(m, e, n)

    print(f'n = {n}')
    print(f'e = {e}')
    print(f'c = {c}')


if __name__ == '__main__':
    encrypt()

