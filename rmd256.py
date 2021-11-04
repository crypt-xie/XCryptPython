# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2021 XCrypt <xcrypt@126.com>
#
# Distributed under terms of the MIT license.

padding =(
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

def SHL(x, n):
   return (((x) << n) & 0xFFFFFFFF)

def ROLc(x,n):
    # print(f'ROTL(n={n})')
    n = n % 32
    return (SHL(x& 0xFFFFFFFF,n) | ((x & 0xFFFFFFFF) >> (32 - n)))

def F(x, y, z):
    return ((x) ^ (y) ^ (z))

def G(x, y, z):
    return (((x) & (y)) | (~(x) & (z)))

def H(x, y, z):
    return (((x) | ~(y)) ^ (z))

def I(x, y, z):
    return (((x) & (z)) | ((y) & ~(z)))

def FF(a, b, c, d, x, s):
    a += F(b, c, d) + (x)
    a = ROLc(a, s)
    return a

def GG(a, b, c, d, x, s):
    a += G((b), (c), (d)) + (x) + 0x5a827999
    a = ROLc((a), (s))
    return a

def HH(a, b, c, d, x, s):
    a += H((b), (c), (d)) + (x) + 0x6ed9eba1
    a = ROLc((a), (s))
    return a

def II(a, b, c, d, x, s):
    a += I((b), (c), (d)) + (x) + 0x8f1bbcdc
    a = ROLc((a), (s))
    return a

def FFF(a, b, c, d, x, s):
    a += F((b), (c), (d)) + (x)
    a = ROLc((a), (s))
    return a

def GGG(a, b, c, d, x, s):
    a += G((b), (c), (d)) + (x) + 0x6d703ef3
    a = ROLc((a), (s))
    return a

def HHH(a, b, c, d, x, s):
    a += H((b), (c), (d)) + (x) + 0x5c4dd124
    a = ROLc((a), (s))
    return a

def III(a, b, c, d, x, s):
    a += I((b), (c), (d)) + (x) + 0x50a28be6
    a = ROLc((a), (s))
    return a

class RMD256:
    def __init__(self):
       self.total = [0, 0]
       self.state = [0x67452301,0xefcdab89,0x98badcfe,0x10325476,
                     0x76543210,0xfedcba98,0x89abcdef,0x01234567]
       self.buf = []
       for i in range(64):
          self.buf.append(0)

    def rmd256_compress(self, buf):
       # /* load words X */
       X = []
       for i in range(16):
          temp = 0
          for j in range(4):
             temp = (temp << 8) | buf[4 * i + 3-j]
          X.append(temp)
       # load state 
       aa  = self.state[0]
       bb  = self.state[1]
       cc  = self.state[2]
       dd  = self.state[3]
       aaa = self.state[4]
       bbb = self.state[5]
       ccc = self.state[6]
       ddd = self.state[7]
	   
       # /* round 1 */
       aa = FF(aa, bb, cc, dd, X[ 0], 11)
       dd = FF(dd, aa, bb, cc, X[ 1], 14)
       cc = FF(cc, dd, aa, bb, X[ 2], 15)
       bb = FF(bb, cc, dd, aa, X[ 3], 12)
       aa = FF(aa, bb, cc, dd, X[ 4],  5)
       dd = FF(dd, aa, bb, cc, X[ 5],  8)
       cc = FF(cc, dd, aa, bb, X[ 6],  7)
       bb = FF(bb, cc, dd, aa, X[ 7],  9)
       aa = FF(aa, bb, cc, dd, X[ 8], 11)
       dd = FF(dd, aa, bb, cc, X[ 9], 13)
       cc = FF(cc, dd, aa, bb, X[10], 14)
       bb = FF(bb, cc, dd, aa, X[11], 15)
       aa = FF(aa, bb, cc, dd, X[12],  6)
       dd = FF(dd, aa, bb, cc, X[13],  7)
       cc = FF(cc, dd, aa, bb, X[14],  9)
       bb = FF(bb, cc, dd, aa, X[15],  8)
       
       # /* parallel round 1 */
       aaa = III(aaa, bbb, ccc, ddd, X[ 5],  8)
       ddd = III(ddd, aaa, bbb, ccc, X[14],  9)
       ccc = III(ccc, ddd, aaa, bbb, X[ 7],  9)
       bbb = III(bbb, ccc, ddd, aaa, X[ 0], 11)
       aaa = III(aaa, bbb, ccc, ddd, X[ 9], 13)
       ddd = III(ddd, aaa, bbb, ccc, X[ 2], 15)
       ccc = III(ccc, ddd, aaa, bbb, X[11], 15)
       bbb = III(bbb, ccc, ddd, aaa, X[ 4],  5)
       aaa = III(aaa, bbb, ccc, ddd, X[13],  7)
       ddd = III(ddd, aaa, bbb, ccc, X[ 6],  7)
       ccc = III(ccc, ddd, aaa, bbb, X[15],  8)
       bbb = III(bbb, ccc, ddd, aaa, X[ 8], 11)
       aaa = III(aaa, bbb, ccc, ddd, X[ 1], 14)
       ddd = III(ddd, aaa, bbb, ccc, X[10], 14)
       ccc = III(ccc, ddd, aaa, bbb, X[ 3], 12)
       bbb = III(bbb, ccc, ddd, aaa, X[12],  6)
       
       #
       tmp = aa
       aa = aaa
       aaa = tmp
	   #aa,aaa=aaa,aa
       
       # /* round 2 */
       aa = GG(aa, bb, cc, dd, X[ 7],  7)
       dd = GG(dd, aa, bb, cc, X[ 4],  6)
       cc = GG(cc, dd, aa, bb, X[13],  8)
       bb = GG(bb, cc, dd, aa, X[ 1], 13)
       aa = GG(aa, bb, cc, dd, X[10], 11)
       dd = GG(dd, aa, bb, cc, X[ 6],  9)
       cc = GG(cc, dd, aa, bb, X[15],  7)
       bb = GG(bb, cc, dd, aa, X[ 3], 15)
       aa = GG(aa, bb, cc, dd, X[12],  7)
       dd = GG(dd, aa, bb, cc, X[ 0], 12)
       cc = GG(cc, dd, aa, bb, X[ 9], 15)
       bb = GG(bb, cc, dd, aa, X[ 5],  9)
       aa = GG(aa, bb, cc, dd, X[ 2], 11)
       dd = GG(dd, aa, bb, cc, X[14],  7)
       cc = GG(cc, dd, aa, bb, X[11], 13)
       bb = GG(bb, cc, dd, aa, X[ 8], 12)
       
       # /* parallel round 2 */
       aaa = HHH(aaa, bbb, ccc, ddd, X[ 6],  9)
       ddd = HHH(ddd, aaa, bbb, ccc, X[11], 13)
       ccc = HHH(ccc, ddd, aaa, bbb, X[ 3], 15)
       bbb = HHH(bbb, ccc, ddd, aaa, X[ 7],  7)
       aaa = HHH(aaa, bbb, ccc, ddd, X[ 0], 12)
       ddd = HHH(ddd, aaa, bbb, ccc, X[13],  8)
       ccc = HHH(ccc, ddd, aaa, bbb, X[ 5],  9)
       bbb = HHH(bbb, ccc, ddd, aaa, X[10], 11)
       aaa = HHH(aaa, bbb, ccc, ddd, X[14],  7)
       ddd = HHH(ddd, aaa, bbb, ccc, X[15],  7)
       ccc = HHH(ccc, ddd, aaa, bbb, X[ 8], 12)
       bbb = HHH(bbb, ccc, ddd, aaa, X[12],  7)
       aaa = HHH(aaa, bbb, ccc, ddd, X[ 4],  6)
       ddd = HHH(ddd, aaa, bbb, ccc, X[ 9], 15)
       ccc = HHH(ccc, ddd, aaa, bbb, X[ 1], 13)
       bbb = HHH(bbb, ccc, ddd, aaa, X[ 2], 11)
       
       tmp = bb
       bb = bbb
       bbb = tmp
       
       # /* round 3 */
       aa = HH(aa, bb, cc, dd, X[ 3], 11)
       dd = HH(dd, aa, bb, cc, X[10], 13)
       cc = HH(cc, dd, aa, bb, X[14],  6)
       bb = HH(bb, cc, dd, aa, X[ 4],  7)
       aa = HH(aa, bb, cc, dd, X[ 9], 14)
       dd = HH(dd, aa, bb, cc, X[15],  9)
       cc = HH(cc, dd, aa, bb, X[ 8], 13)
       bb = HH(bb, cc, dd, aa, X[ 1], 15)
       aa = HH(aa, bb, cc, dd, X[ 2], 14)
       dd = HH(dd, aa, bb, cc, X[ 7],  8)
       cc = HH(cc, dd, aa, bb, X[ 0], 13)
       bb = HH(bb, cc, dd, aa, X[ 6],  6)
       aa = HH(aa, bb, cc, dd, X[13],  5)
       dd = HH(dd, aa, bb, cc, X[11], 12)
       cc = HH(cc, dd, aa, bb, X[ 5],  7)
       bb = HH(bb, cc, dd, aa, X[12],  5)
       
       # /* parallel round 3 */
       aaa = GGG(aaa, bbb, ccc, ddd, X[15],  9)
       ddd = GGG(ddd, aaa, bbb, ccc, X[ 5],  7)
       ccc = GGG(ccc, ddd, aaa, bbb, X[ 1], 15)
       bbb = GGG(bbb, ccc, ddd, aaa, X[ 3], 11)
       aaa = GGG(aaa, bbb, ccc, ddd, X[ 7],  8)
       ddd = GGG(ddd, aaa, bbb, ccc, X[14],  6)
       ccc = GGG(ccc, ddd, aaa, bbb, X[ 6],  6)
       bbb = GGG(bbb, ccc, ddd, aaa, X[ 9], 14)
       aaa = GGG(aaa, bbb, ccc, ddd, X[11], 12)
       ddd = GGG(ddd, aaa, bbb, ccc, X[ 8], 13)
       ccc = GGG(ccc, ddd, aaa, bbb, X[12],  5)
       bbb = GGG(bbb, ccc, ddd, aaa, X[ 2], 14)
       aaa = GGG(aaa, bbb, ccc, ddd, X[10], 13)
       ddd = GGG(ddd, aaa, bbb, ccc, X[ 0], 13)
       ccc = GGG(ccc, ddd, aaa, bbb, X[ 4],  7)
       bbb = GGG(bbb, ccc, ddd, aaa, X[13],  5)
       
       #
       tmp = cc
       cc = ccc
       ccc = tmp
       
       # /* round 4 */
       aa = II(aa, bb, cc, dd, X[ 1], 11)
       dd = II(dd, aa, bb, cc, X[ 9], 12)
       cc = II(cc, dd, aa, bb, X[11], 14)
       bb = II(bb, cc, dd, aa, X[10], 15)
       aa = II(aa, bb, cc, dd, X[ 0], 14)
       dd = II(dd, aa, bb, cc, X[ 8], 15)
       cc = II(cc, dd, aa, bb, X[12],  9)
       bb = II(bb, cc, dd, aa, X[ 4],  8)
       aa = II(aa, bb, cc, dd, X[13],  9)
       dd = II(dd, aa, bb, cc, X[ 3], 14)
       cc = II(cc, dd, aa, bb, X[ 7],  5)
       bb = II(bb, cc, dd, aa, X[15],  6)
       aa = II(aa, bb, cc, dd, X[14],  8)
       dd = II(dd, aa, bb, cc, X[ 5],  6)
       cc = II(cc, dd, aa, bb, X[ 6],  5)
       bb = II(bb, cc, dd, aa, X[ 2], 12)
       
       # /* parallel round 4 */
       aaa = FFF(aaa, bbb, ccc, ddd, X[ 8], 15)
       ddd = FFF(ddd, aaa, bbb, ccc, X[ 6],  5)
       ccc = FFF(ccc, ddd, aaa, bbb, X[ 4],  8)
       bbb = FFF(bbb, ccc, ddd, aaa, X[ 1], 11)
       aaa = FFF(aaa, bbb, ccc, ddd, X[ 3], 14)
       ddd = FFF(ddd, aaa, bbb, ccc, X[11], 14)
       ccc = FFF(ccc, ddd, aaa, bbb, X[15],  6)
       bbb = FFF(bbb, ccc, ddd, aaa, X[ 0], 14)
       aaa = FFF(aaa, bbb, ccc, ddd, X[ 5],  6)
       ddd = FFF(ddd, aaa, bbb, ccc, X[12],  9)
       ccc = FFF(ccc, ddd, aaa, bbb, X[ 2], 12)
       bbb = FFF(bbb, ccc, ddd, aaa, X[13],  9)
       aaa = FFF(aaa, bbb, ccc, ddd, X[ 9], 12)
       ddd = FFF(ddd, aaa, bbb, ccc, X[ 7],  5)
       ccc = FFF(ccc, ddd, aaa, bbb, X[10], 15)
       bbb = FFF(bbb, ccc, ddd, aaa, X[14],  8)
       
       tmp = dd
       dd = ddd
       ddd = tmp

       #/* combine results */
       self.state[0] += aa
       self.state[1] += bb
       self.state[2] += cc
       self.state[3] += dd
       self.state[4] += aaa
       self.state[5] += bbb
       self.state[6] += ccc
       self.state[7] += ddd

       for i in range(8):
           self.state[i] = self.state[i] & 0xffffffff
       #    print(f'state[{i}] = %x'%self.state[i])


    def rmd256_update(self,data,ilen):
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
            self.rmd256_compress(self.buf)
            used += fill
            ilen -= fill
            left = 0

        while ilen >= 64 :
            self.rmd256_compress(data[used:used+64])
            used += 64
            ilen -= 64

        if ilen > 0:
            # print('ilen=',ilen,'used=',used)
            for i in range(ilen):
                self.buf[left+i] = data[used+i]

    def rmd256_finish(self):
        high = (self.total[0] >> 29)|(self.total[1] << 3)
        low = (self.total[0] << 3)
        msglen = []
        msglen.append(low & 0x000000ff)
        msglen.append((low & 0x0000ff00) >> 8)
        msglen.append((low & 0x00ff0000) >> 16)
        msglen.append((low & 0xff000000) >> 24)
        msglen.append(high & 0x000000ff)
        msglen.append((high & 0x0000ff00) >> 8)
        msglen.append((high & 0x00ff0000) >> 16)
        msglen.append((high & 0xff000000) >> 24)
        last = self.total[0] & 0x3F
        if last < 56:
            padn = 56 - last
        else:
            padn = 120 - last
        # 处理填充字段
        self.rmd256_update(padding[0:padn], padn)
        # 处理8字节长度字段
        self.rmd256_update(msglen, 8)
        c = []
        for i in range(8):
            c.append(self.state[i] & 0x000000ff)
            c.append((self.state[i] & 0x0000ff00) >> 8)
            c.append((self.state[i] & 0x00ff0000) >> 16)
            c.append((self.state[i] & 0xff000000) >> 24)
        return c

    def rmd256_hash(self, data, ilen):
       self.rmd256_update(data, ilen)
       hash = self.rmd256_finish()
       return hash


def byte2hex(msg):  # byte数组转换成16进制字符串
    ml = len(msg)
    hexstr = ""
    for i in range(ml):
       hexstr = hexstr + ('%02x' % msg[i])
    return hexstr

if __name__ == '__main__':
    # rmd256摘要算法
    str = ''
    data = list(map(lambda x: ord(x), str))
    print(data,len(data))
    a = RMD256()
    hash =a.rmd256_hash(data, len(data))
    print("摘要值:", end='')
    print(byte2hex(hash))
    print('-----------------------')
    str = 'a'
    data = list(map(lambda x: ord(x), str))
    print(data,len(data))
    a = RMD256()
    hash =a.rmd256_hash(data, len(data))
    print("摘要值:", end='')
    print(byte2hex(hash))
    print('-----------------------')
    str = 'abc'
    data = list(map(lambda x: ord(x), str))
    print(data,len(data))
    a = RMD256()
    hash =a.rmd256_hash(data, len(data))
    print("摘要值:", end='')
    print(byte2hex(hash))
    print('-----------------------')
    str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    data = list(map(lambda x: ord(x), str))
    print(data,len(data))
    a = RMD256()
    hash =a.rmd256_hash(data, len(data))
    print("摘要值:", end='')
    print(byte2hex(hash))
    #print_bytes_hex(hash)

        