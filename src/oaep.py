from rsa import *
import secrets
import hashlib


def get_hash(string):
    """
    hash 生成函数，使用sha1
    :param string:写入的字符串, str
    :return: 16进制hash结果，str
    """
    if len(string) > 2 ** 62 - 2:
        raise IndexError('The tag is too long!')
    sha = hashlib.sha1(string)
    return sha.hexdigest()


def get_seed(length):
    """
    种子生成
    :param length: 长度, int
    :return: 随机生成的种子，str
    """
    return secrets.token_hex(length)


def mgf(mgf_seed, mask_len, hlen):
    """
    mgf函数
    :param mgf_seed:mgf 种子参数, str
    :param mask_len: 掩码长度，int
    :param hlen: 哈希长度,int
    :return: 生成的16进制掩码，str
    """
    if mask_len > (2 ** 32) * hlen:
        raise IndexError('The mask length is too long!')
    t = b''
    if len(mgf_seed) % 2 != 0:
        mgf_seed = '0' + mgf_seed
    seed = bytes.fromhex(mgf_seed)
    rounds = mask_len // hlen
    if mask_len % hlen == 0:
        rounds -= 1
    for i in range(rounds + 1):
        temp = seed + bytes.fromhex('%08x' % i)
        t += bytes.fromhex(get_hash(temp))
    return t[:mask_len].hex()


def oaep_encrypt(n, e, m, seed=get_seed(20), tag=b''):
    """
    oaep编码及加密函数
    :param n: RSA参数n, int
    :param e: RSA参数e, int
    :param m: 明文, bytes or str
    :param seed: 种子，str, 默认随机生成
    :param tag: 标签, bytes, 默认b''
    :return:
    """
    m_copy = m.encode() if isinstance(m, str) else m
    k = (len(hex(n)[2:]) // 2) + 1 if len(hex(n)
                                          [2:]) % 2 == 1 else len(hex(n)[2:]) // 2
    hlen = 20
    mlen = len(m_copy)
    if mlen > (k - 2 - 2 * hlen):
        raise IndexError('The message is too long!')
    lhash = get_hash(tag)
    if k - 2 * hlen - mlen - 2 > 0:
        ps = '00' * (k - 2 - 2 * hlen - mlen)
    else:
        ps = ''
    db = lhash + ps + '01' + m_copy.hex()
    db_mask = mgf(seed, k - hlen - 1, hlen)
    masked_db = '{:0{}x}'.format(
        int(db, 16) ^ int(db_mask, 16), (k - hlen - 1) * 2)
    seed_mask = mgf(masked_db, hlen, hlen)
    masked_seed = '{:0{}x}'.format(
        int(seed, 16) ^ int(seed_mask, 16), 2 * hlen)
    em = '00' + masked_seed + masked_db
    c = encrypt(int(em, 16), n, e)
    result = '{:0{}x}'.format(c, 2 * k)
    return bytes.fromhex(result)


def oaep_decrypt(p, q, d, c, tag=b''):
    """
    OAEP解码及解密函数
    :param p: RSA参数p, int
    :param q: RSA参数q, int
    :param d: RSA私钥d, int
    :param c: 密文c, bytes or str
    :param tag: 标签，bytes, 默认b''
    :return:
    """
    c_copy = c.encode() if isinstance(c, str) else c
    hlen = 20
    n = p * q
    k = (len(hex(n)[2:]) // 2) + 1 if len(hex(n)
                                          [2:]) % 2 == 1 else len(hex(n)[2:]) // 2
    clen = len(c_copy)
    if clen != k or (k < 2 * hlen + 2):
        raise IndexError('You may input c with wrong length!')
    cipher = int(c_copy.hex(), 16)
    em = '{:0{}x}'.format(decrypt(cipher, p, q, d), k * 2)
    lhash = get_hash(tag)
    y = em[:2]
    if y != '00':
        raise ValueError('You may get wrong decrypt result, check your index!')
    masked_seed = em[2:2 * hlen + 2]
    masked_db = em[2 * hlen + 2:]
    seed_mask = mgf(masked_db, hlen, hlen)
    seed = '{:0{}x}'.format(int(seed_mask, 16) ^
                            int(masked_seed, 16), 2 * hlen)
    db_mask = mgf(seed, k - hlen - 1, hlen)
    db = '{:0{}x}'.format(int(db_mask, 16) ^ int(
        masked_db, 16), (k - hlen - 1) * 2)
    chash = db[:2 * hlen]
    if lhash != chash:
        raise ValueError('The hash is wrong. Are you use the correct tag?')
    i = 2 * hlen
    while db[i:i + 2] == '00':
        i += 2
    if db[i:i + 2] != '01':
        raise ValueError(
            'We do not find the end byte for the ps. Is there anything wrong?')
    i += 2
    m = db[i:]
    return bytes.fromhex(m)


def main():
    pq, pub, pri = generate_key(128)
    c = oaep_encrypt(pub[0], pub[1], "I'm fucking coming")
    print(c)
    print(oaep_decrypt(pq[0], pq[1], pri[1], c))


if __name__ == '__main__':
    main()
