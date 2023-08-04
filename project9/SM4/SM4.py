import math
import binascii
import tool

def sbox(x):
    row = (x >> 4) & 0xf
    col = x & 0xf
    return tool.sbox[row][col]

def t(x):
    a0 = (x >> 24) & 0xff
    a1 = (x >> 16) & 0xff
    a2 = (x >> 8) & 0xff
    a3 = (x >> 0) & 0xff

    return ((sbox(a0) << 24) | (sbox(a1) << 16) | (sbox(a2) << 8) | sbox(a3))

def L(m):
    return (m ^ ((m << 2) & 0xffffffff) ^ ((m << 10) & 0xffffffff) ^ ((m << 18) & 0xffffffff) ^ (
            (m << 24) & 0xffffffff))

def T(x):
    B = t(x)
    return L(B)

def L_(B):
    return (B ^ ((B << 13) & 0xffffffff) ^ ((B << 23) & 0xffffffff))

def T_(x):
    B = t(x)
    return L_(B)

def K(MK0, MK1, MK2, MK3):
    K = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    K[0] = MK0 ^ tool.FK0
    K[1] = MK1 ^ tool.FK1
    K[2] = MK2 ^ tool.FK2
    K[3] = MK3 ^ tool.FK3
    for i in range(32):
        tool.rk[i] = K[i + 4] = K[i] ^ T_(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ tool.CK[i])


def SM4(x):
    X = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
         0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    X[0] = (x >> 96) & 0xffffffff
    X[1] = (x >> 64) & 0xffffffff
    X[2] = (x >> 32) & 0xffffffff
    X[3] = (x >> 0) & 0xffffffff
    for i in range(32):
        X[i + 4] = X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ tool.rk[i])
    Y = (X[35] << 96) ^ (X[34] << 64) ^ (X[33] << 32) ^ X[32]
    return Y


def SM4Decode(x):
    X = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
         0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    X[0] = (x >> 96) & 0xffffffff
    X[1] = (x >> 64) & 0xffffffff
    X[2] = (x >> 32) & 0xffffffff
    X[3] = (x >> 0) & 0xffffffff
    for i in range(32):
        X[i + 4] = X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ tool.rk[31 - i])
    return (X[35] << 96) ^ (X[34] << 64) ^ (X[33] << 32) ^ X[32]


def BitsFill(P):
    if len(P) % 16 == 0:
        fillByte = chr(0x10)
        dataFill = "{0:{1}<{2}}".format(P, fillByte, len(P) + 16)
    else:
        n = math.ceil(len(P) / 16)
        fillByte = chr(16 * n - len(P))
        dataFill = "{0:{1}<{2}}".format(P, fillByte, 16 * n)

    strHex = dataFill.encode().hex()

    dataHex = int(strHex, 16)
    bits = len(strHex) * 4
    return dataHex, bits, fillByte


if __name__ == '__main__':
    MK = "202100460098"
    MK, bits1, fill1 = BitsFill(MK)
    if bits1 != 128:
        print("输入错误。")
        exit()
    MK0 = (MK >> 96) & 0Xffffffff
    MK1 = (MK >> 64) & 0Xffffffff
    MK2 = (MK >> 32) & 0Xffffffff
    MK3 = (MK >> 0) & 0Xffffffff
    K(MK0, MK1, MK2, MK3)

    P="abcdefghijklmnopqrstuvwxyz"
    print("明文为",P)
    P, bits2, fill2 = BitsFill(P)
    temp = bits2

    C = " "
    print("\n密文为：")
    while (bits2 != 0):
        bits2 = bits2 - 128
        Pk = (P >> bits2) & 0Xffffffffffffffffffffffffffffffff
        C = C + hex(SM4(Pk))[2:]
    print(C)

    bits2 = temp
    C = int(C, 16)
    P = ""
    print("\n解密为：")
    while (bits2 != 0):
        bits2 = bits2 - 128
        Ck = (C >> bits2) & 0Xffffffffffffffffffffffffffffffff
        P = P + hex(SM4Decode(Ck))[2:]
    print(P)

    P = binascii.a2b_hex(P).decode()
    fill2 = ord(fill2)
