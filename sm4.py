# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2021 XCrypt <xcrypt@126.com>
#
# Distributed under terms of the MIT license.

# Sbox table: 8bits input convert to 8 bits output
SboxTable = [
[0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05],
[0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99],
[0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62],
[0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6],
[0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8],
[0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35],
[0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87],
[0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e],
[0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1],
[0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3],
[0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f],
[0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51],
[0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8],
[0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0],
[0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84],
[0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48]]

# System parameter
FK = (0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc)

# fixed parameter
CK = (
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279)


def SMS4CROL(uval, bits):
    return (((uval << bits)&0xffffffff) | (uval >> (0x20 - bits)))


def SMS4Sbox(inch):
    # print("inch = ",inch)
    retVal = SboxTable[inch >> 4][inch & 0x0f]
    return retVal


def SMS4CalciRK(a):
    # print('a=',a)
    b0 = SMS4Sbox(a & 0x000000ff)
    b1 = SMS4Sbox((a & 0x0000ff00) >> 8)
    b2 = SMS4Sbox((a & 0x00ff0000) >> 16)
    b3 = SMS4Sbox((a & 0xff000000) >> 24)
    b = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    c = b^(SMS4CROL(b, 13)) ^ (SMS4CROL(b, 23))
    # print('b,c=',b,c)
    return c


def SMS4Lt(a):
    b0 = SMS4Sbox(a & 0x000000ff)
    b1 = SMS4Sbox((a & 0x0000ff00) >> 8)
    b2 = SMS4Sbox((a & 0x00ff0000) >> 16)
    b3 = SMS4Sbox((a & 0xff000000) >> 24)
    b = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    c = b ^ (SMS4CROL(b, 2)) ^ (SMS4CROL(b, 10)) ^ (SMS4CROL(b, 18)) ^ (SMS4CROL(b, 24))
    return c


def SMS4T(a):
    return (SMS4Lt(a))


def SMS4F(x0, x1, x2, x3, rk):
    return (x0^SMS4Lt(x1^x2^x3^rk))


class SM4(object):
    def __init__(self, K):
        # 通过密钥K生成实例，密钥K位数不足补零
        self.K = []
        for i in range(len(K)):
            self.K.append(K[i])
        while len(self.K) < 16:
            self.K.append(0)
        self.W = self.KeyExpansion()

    def KeyExpansion(self):
        # 密钥扩展函数，密钥 K 扩展生成 32个字
        w = []
        for i in range(4):
            temp = 0
            for j in range(4):
                temp = (temp << 8) | self.K[4 * i + j]
            w.append(temp ^ FK[i])
            print(f'temp=0x%x' % temp,f'FK=0x%x'%FK[i])
        for i in range(32):
            temp = w[i] ^ SMS4CalciRK(w[i+1] ^ w[i+2] ^ w[i+3] ^ CK[i])
            w.append(temp)
            print(f'rk{i}=0x%x'%temp)
        return w

    def Encrypt(self, m):
        # 加密
        # 明文不足16*8bits补零
        while len(m) % 16 != 0:
            m.append(0)
        c = []
        for i in range(len(m) // 16):
            # 对每一个16*8bits的块进行循环
            mtx = []
            # 把16字节明文转换成4个双字
            for j in range(4):
                temp = 0
                for k in range(4):
                    temp = (temp << 8) | m[16*i + 4 * j + k]
                # print('mtx=0x%x'%temp)
                mtx.append(temp)
            # 执行32轮加密运算
            for j in range(32):
                temp = SMS4F(mtx[j], mtx[j+1], mtx[j+2], mtx[j+3], self.W[j+4])
                # print(f'mtx{j}=0x%x'%temp)
                mtx.append(temp)
            #
            for j in range(4):
                c.append((mtx[35-j] & 0xff000000) >> 24)
                c.append((mtx[35-j] & 0x00ff0000) >> 16)
                c.append((mtx[35-j] & 0x0000ff00) >> 8)
                c.append (mtx[35-j] & 0x000000ff)
            # print("c=",c)
        return c

    def Decrypt(self, m):
        # 解密
        c = []
        for i in range(len(m) // 16):
            # 对每一个16*8bits的块进行循环
            mtx = []
            # 把16字节明文转换成4个双字
            for j in range(4):
                temp = 0
                for k in range(4):
                    temp = (temp << 8) | m[16*i + 4 * j + k]
                mtx.append(temp)
                print('mtx=0x%x' % temp)
            # 执行32轮解密运算
            for j in range(32):
                temp = SMS4F(mtx[j], mtx[j+1], mtx[j+2], mtx[j+3], self.W[35-j]);
                mtx.append(temp)
                # print(f'mtx{j}=0x%x' % temp)
            # 把双字转换成字节拼接
            for j in range(4):
                c.append((mtx[35-j] & 0xff000000) >> 24)
                c.append((mtx[35-j] & 0x00ff0000) >> 16)
                c.append((mtx[35-j] & 0x0000ff00) >> 8)
                c.append (mtx[35-j] & 0x000000ff)
        return c

    def getK(self):
        # 返回密钥K
        return self.K


def print_bytes_hex(m):
    for i in m:
        print(hex(i)[2:].rjust(2, '0'), end='')
    print()


def hex2byte(msg):  # 16进制字符串转换成byte数组
    ml = len(msg)
    if ml % 2 != 0:
        msg = '0' + msg
    ml = int(len(msg) / 2)
    msg_byte = []
    for i in range(ml):
        msg_byte.append(int(msg[i * 2:i * 2 + 2], 16))
    return msg_byte

def byte2hex(msg):  # byte数组转换成16进制字符串
    ml = len(msg)
    hexstr = ""
    for i in range(ml):
        hexstr = hexstr + ('%02x' % msg[i])
    return hexstr

if __name__ == '__main__':
    # SM4算法
    # 密钥不足128bits 添零，多余128bits 截取前128bits
    # messages 不足128bits的倍数 补零
    m = '0123456789abcdeffedcba9876543210'
    key = '0123456789abcdeffedcba9876543210'
    ml = hex2byte(m)
    keyl = hex2byte(key)
    a = SM4(keyl)
    cc = a.Encrypt(ml)
    mm = a.Decrypt(cc)
    print("明文:", end='')
    print(byte2hex(ml))
    print("密钥:", end='')
    print(byte2hex(keyl))
    print("密文:", end='')
    print(byte2hex(cc)) # 以bytes输出
    print("解密:", end='')
    print(byte2hex(mm))
    print('--------------------')
    print('加密1000000次')
    m = '0123456789abcdeffedcba9876543210'
    key = '0123456789abcdeffedcba9876543210'
    ml = hex2byte(m)
    keyl = hex2byte(key)
    a = SM4(keyl)
    for i in range(1000000):
        if i==0:
            cc = a.Encrypt(ml)
        else:
            cc = a.Encrypt(cc)
        if i%1000 == 0:
            print('i=',i)
    print(byte2hex(cc))
