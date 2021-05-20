from random import randint


def fast_pow(x, n, m):  # 快速幂
    result = 1
    while n > 0:
        if n % 2 == 1:
            result = result * x % m
        x = x * x % m
        n = n // 2
    return result % m


def miller_rabin(p):  # 本题主函数
    random_time = 10  # 用一个很小的数亦可；这个数是随手打的
    if p < 3:
        return p == 2  # 先进行2判定
    q = p - 1
    t = 0
    while q % 2 == 0:  # 先把q和t求好
        q //= 2
        t += 1
    for i in range(1, random_time + 1):  # 进行random_time次检测
        a = randint(2, p - 1)
        v = fast_pow(a, q, p)
        if v == 1 or v == p - 1:  # 进行1或-1判定
            continue
        for j in range(t + 1):
            v = v * v % p
            if v == p - 1:
                break
        else:
            return False
    return True


def is_prime(p):
    return miller_rabin(p)


def extended_gcd(a, b):  # 扩展欧几里得算法
    if a[2] == 0:
        return b[1]
    else:
        q = b[2] // a[2]
        t1 = b[0] - q * a[0]
        t2 = b[1] - q * a[1]
        t3 = b[2] - q * a[2]
        return extended_gcd([t1, t2, t3], a)


def get_inv(num, mod):
    nums = [0, 1, num]
    mods = [1, 0, mod]
    return extended_gcd(nums, mods)


def gcd(a, b):
    return a if b == 0 else gcd(b, a % b)


def get_mi(ls):
    m = 1
    result = []
    for pair in ls:
        m *= pair[0]
    for pair in ls:
        result.append([pair[0], m // pair[0]])
    return [result, m]


def get_ms_inv(ls):
    result = []
    for pair in ls:
        result.append(get_inv(pair[1], pair[0]))
    return result


def crt(ls):
    x = 0
    ms, m = get_mi(ls)
    es = get_ms_inv(ms)
    for i in range(len(ls)):
        x = (x + ms[i][1] * es[i] * ls[i][1]) % m
    return x


def main():
    print(crt([[23, 283], [28, 102], [33, 23]]))


if __name__ == '__main__':
    main()
