import secrets
from RSAlib import *


def generate_prime(n):
    """
    素数对生成
    :param n:指定素数长度，单位字节，int
    :return: 一对素数对，list[int]
    """
    p = int(secrets.token_hex(n), 16)
    while not is_prime(p):
        if p % 2 == 0:
            p += 1
        else:
            p += 2
    q = int(secrets.token_hex(n), 16)
    while not is_prime(q) or p == q:
        if q % 2 == 0:
            q += 1
        else:
            q += 2
    return [p, q]


def generate_key(lens):
    """
    密钥生成
    :param lens:p,q长度（字节），int
    :return: 素数对[p,q], 公钥[n,e], 保护参数[phi,d]
    """
    p, q = generate_prime(lens)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = get_inv(e, phi)
    return [[p, q], [n, e], [phi, d]]


def encrypt(plaintext, n, e):
    """
    RSA加密实现
    :param plaintext:明文消息, int
    :param n: 公钥n, int
    :param e: 公钥e, int
    :return: RSA加密结果
    """
    if plaintext > n - 1:
        raise IndexError(
            'You are trying to encrypt a message with invalid length.')
    return fast_pow(plaintext, e, n)


def decrypt(ciphertext, p, q, d):
    """
    RSA 解密实现（CRT加速）
    :param ciphertext: 密文消息, int
    :param p: 加密参数p, int
    :param q: 加密参数q, int
    :param d: 私钥d, int
    :return: RSA解密结果, int
    """
    cipher_p = ciphertext % p
    cipher_q = ciphertext % q
    d_p = d % (p - 1)
    d_q = d % (q - 1)
    x_p = fast_pow(cipher_p, d_p, p)
    x_q = fast_pow(cipher_q, d_q, q)
    return crt([[p, x_p], [q, x_q]])


def decrypt_without_pq(ciphertext, n, d):
    return fast_pow(ciphertext, d, n)


def main():
    pq, pub, pri = generate_key(128)
    ciphertext = encrypt(0x92374924d23497ad329487129, pub[0], pub[1])
    print(ciphertext)
    print(hex(decrypt(ciphertext, pq[0], pq[1], pri[1])))


if __name__ == '__main__':
    main()
