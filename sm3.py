# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2021 XCrypt <xcrypt@126.com>
#
# Distributed under terms of the MIT license.

sm3_padding =(
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

def FF0(x,y,z):
    return ((x) ^ (y) ^ (z))

def FF1(x,y,z):
    return (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

def GG0(x,y,z):
    return ( (x) ^ (y) ^ (z))

def GG1(x,y,z):
    return (((x) & (y)) | ( (~(x)) & (z)) )

def SHL(x,n):
    return (((x) << n) & 0xFFFFFFFF)

def ROTL(x,n):
    # print(f'ROTL(n={n})')
    n = n % 32
    return (SHL(x,n) | ((x & 0xFFFFFFFF) >> (32 - n)))

def P0(x):
    return ((x) ^  ROTL((x),9) ^ ROTL((x),17))

def P1(x):
    return ((x) ^  ROTL((x),15) ^ ROTL((x),23))

class SM3:
    def __init__(self):
        self.total=[0,0]
        self.state=[0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
                    0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E]
        self.buf = []
        for i in range(64):
            self.buf.append(0)

    def sm3_process(self,data):
        print('sm3_proc:',data,len(data))
        # 初始化T
        T = []
        for j in range(16):
            T.append(0x79CC4519)
        for j in range(16,64):
            T.append(0x7A879D8A)
        # 初始化W
        W = []
        for i in range(16):
            temp = 0
            for j in range(4):
                temp = (temp << 8) | data[4 * i + j]
            W.append(temp)
        #
        for j in range(16,68):
            temp = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6]
            W.append(temp)
        #
        W1 = []
        for j in range(64):
            W1.append(W[j] ^ W[j+4])
        #
        A = self.state[0]
        B = self.state[1]
        C = self.state[2]
        D = self.state[3]
        E = self.state[4]
        F = self.state[5]
        G = self.state[6]
        H = self.state[7]
        #
        for j in range(16):
            SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ ROTL(A, 12)
            TT1 = (FF0(A, B, C) + D + SS2 + W1[j]) & 0xFFFFFFFF
            TT2 = (GG0(E, F, G) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = ROTL(B, 9)
            B = A
            A = TT1
            H = G
            G = ROTL(F, 19)
            F = E
            E = P0(TT2)
        #
        for j in range(16,64):
            SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7)
            SS2 = SS1 ^ ROTL(A, 12)
            TT1 = (FF1(A, B, C) + D + SS2 + W1[j])&0xFFFFFFFF
            TT2 = (GG1(E, F, G) + H + SS1 + W[j])&0xFFFFFFFF
            D = C
            C = ROTL(B, 9)
            B = A
            A = TT1
            H = G
            G = ROTL(F, 19)
            F = E
            E = P0(TT2)
        #
        self.state[0] ^= A
        self.state[1] ^= B
        self.state[2] ^= C
        self.state[3] ^= D
        self.state[4] ^= E
        self.state[5] ^= F
        self.state[6] ^= G
        self.state[7] ^= H

    def sm3_update(self,data,ilen):
        if ilen <= 0:
            return None
        left = self.total[0] & 0x3F
        fill = 64 - left

        self.total[0] += ilen
        self.total[0] &= 0xFFFFFFFF

        if self.total[0] < ilen:
            self.total[1] += 1

        used = 0
        if left != 0 and ilen >= fill:
            for i in range(64-left):
                self.buf[left+i] = data[i]
            # print('buf=',self.buf)
            self.sm3_process(self.buf)
            used += fill
            ilen -= fill
            left = 0

        while ilen >= 64 :
            self.sm3_process(data[used:used+64])
            used += 64
            ilen -= 64

        if ilen > 0:
            # print('ilen=',ilen,'used=',used)
            for i in range(ilen):
                self.buf[left+i] = data[used+i]

    def sm3_finish(self):
        high = (self.total[0] >> 29)|(self.total[1] << 3)
        low = (self.total[0] << 3)
        msglen = []
        msglen.append((high & 0xff000000) >> 24)
        msglen.append((high & 0x00ff0000) >> 16)
        msglen.append((high & 0x0000ff00) >> 8)
        msglen.append(high & 0x000000ff)
        msglen.append((low & 0xff000000) >> 24)
        msglen.append((low & 0x00ff0000) >> 16)
        msglen.append((low & 0x0000ff00) >> 8)
        msglen.append(low & 0x000000ff)
        last = self.total[0] & 0x3F
        if last < 56:
            padn = 56 - last
        else:
            padn = 120 - last
        self.sm3_update(sm3_padding[0:padn], padn)
        self.sm3_update(msglen, 8)
        c = []
        for i in range(8):
            c.append((self.state[i] & 0xff000000) >> 24)
            c.append((self.state[i] & 0x00ff0000) >> 16)
            c.append((self.state[i] & 0x0000ff00) >> 8)
            c.append(self.state[i] & 0x000000ff)
        return c

    def sm3_hash(self,data, ilen):
        self.sm3_update(data, ilen)
        hash = self.sm3_finish()
        return hash


def print_bytes_hex(m):
    for i in m:
        print(hex(i)[2:].rjust(2, '0'), end='')
    print()


def str2byte(msg):  # 字符串转换成byte数组
    ml = len(msg)
    msg_byte = []
    msg_bytearray = msg  # 如果加密对象是字符串，则在此对msg做encode()编码即可，否则不编码
    for i in range(ml):
        msg_byte.append(msg_bytearray[i])
    return msg_byte


def byte2str(msg):  # byte数组转字符串
    ml = len(msg)
    str1 = b""
    for i in range(ml):
        str1 += b'%c' % msg[i]
    return str1.decode('utf-8')


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
    # SM3摘要算法
    str = 'abc'
    data = list(map(lambda x: ord(x), str))
    # print(data,len(data))
    a = SM3()
    hash =a.sm3_hash(data, len(data))
    print("摘要值:", end='')
    print(byte2hex(hash))
    print('-----------------------')
    str = 'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd'
    data = list(map(lambda x: ord(x), str))
    # print(data,len(data))
    a = SM3()
    hash =a.sm3_hash(data, len(data))
    print("摘要值:", end='')
    print(byte2hex(hash))
    #print_bytes_hex(hash)