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
	
def J(x, y, z):
    return ((x) ^ ((y) | ~(z)))

def FF(a, b, c, d, e, x, s):
    a += F(b, c, d) + (x)
    a = ROLc(a, s) + (e)
    c = ROLc((c), 10)
    return a, c

def GG(a, b, c, d, e, x, s):
    a += G((b), (c), (d)) + (x) + 0x5a827999
    a = ROLc((a), (s)) + (e)
    c = ROLc((c), 10)
    return a, c

def HH(a, b, c, d, e, x, s):
    a += H((b), (c), (d)) + (x) + 0x6ed9eba1
    a = ROLc((a), (s)) + (e)
    c = ROLc((c), 10)
    return a, c

def II(a, b, c, d, e, x, s):
    a += I((b), (c), (d)) + (x) + 0x8f1bbcdc
    a = ROLc((a), (s)) + (e)
    c = ROLc((c), 10)
    return a, c

def JJ(a, b, c, d, e, x, s):
    a += J((b), (c), (d)) + (x) + 0xa953fd4e
    a = ROLc((a), (s)) + (e)
    c = ROLc((c), 10)
    return a, c
	
def FFF(a, b, c, d, e, x, s):
    a += F((b), (c), (d)) + (x)
    a = ROLc((a), (s)) + (e)
    c = ROLc((c), 10)
    return a, c

def GGG(a, b, c, d, e, x, s):
    a += G((b), (c), (d)) + (x) + 0x7a6d76e9
    a = ROLc((a), (s)) + (e)
    c = ROLc((c), 10)
    return a, c

def HHH(a, b, c, d, e, x, s):
    a += H((b), (c), (d)) + (x) + 0x6d703ef3
    a = ROLc((a), (s)) + (e)
    c = ROLc((c), 10)
    return a, c

def III(a, b, c, d, e, x, s):
    a += I((b), (c), (d)) + (x) + 0x5c4dd124
    a = ROLc((a), (s)) + (e)
    c = ROLc((c), 10);
    return a, c

def JJJ(a, b, c, d, e, x, s):
    a += J((b), (c), (d)) + (x) + 0x50a28be6
    a = ROLc((a), (s)) + (e)
    c = ROLc((c), 10)
    return a, c
	
class RMD160:
    def __init__(self):
       self.total = [0, 0]
       self.state = [0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0]
       self.buf = []
       for i in range(64):
          self.buf.append(0)

    def rmd160_compress(self, buf):
       # /* load words X */
       X = []
       for i in range(16):
          temp = 0
          for j in range(4):
             temp = (temp << 8) | buf[4 * i + 3-j]
          X.append(temp)
       # load state 
       aa = aaa = self.state[0]
       bb = bbb = self.state[1]
       cc = ccc = self.state[2]
       dd = ddd = self.state[3]
       ee = eee = self.state[4]
       # /* round 1 */
       aa, cc = FF(aa, bb, cc, dd, ee, X[ 0], 11)
       ee, bb = FF(ee, aa, bb, cc, dd, X[ 1], 14)
       dd, aa = FF(dd, ee, aa, bb, cc, X[ 2], 15)
       cc, ee = FF(cc, dd, ee, aa, bb, X[ 3], 12)
       bb, dd = FF(bb, cc, dd, ee, aa, X[ 4],  5)
       aa, cc = FF(aa, bb, cc, dd, ee, X[ 5],  8)
       ee, bb = FF(ee, aa, bb, cc, dd, X[ 6],  7)
       dd, aa = FF(dd, ee, aa, bb, cc, X[ 7],  9)
       cc, ee = FF(cc, dd, ee, aa, bb, X[ 8], 11)
       bb, dd = FF(bb, cc, dd, ee, aa, X[ 9], 13)
       aa, cc = FF(aa, bb, cc, dd, ee, X[10], 14)
       ee, bb = FF(ee, aa, bb, cc, dd, X[11], 15)
       dd, aa = FF(dd, ee, aa, bb, cc, X[12],  6)
       cc, ee = FF(cc, dd, ee, aa, bb, X[13],  7)
       bb, dd = FF(bb, cc, dd, ee, aa, X[14],  9)
       aa, cc = FF(aa, bb, cc, dd, ee, X[15],  8)
       # /* round 2 */
       ee, bb = GG(ee, aa, bb, cc, dd, X[ 7],  7)
       dd, aa = GG(dd, ee, aa, bb, cc, X[ 4],  6)
       cc, ee = GG(cc, dd, ee, aa, bb, X[13],  8)
       bb, dd = GG(bb, cc, dd, ee, aa, X[ 1], 13)
       aa, cc = GG(aa, bb, cc, dd, ee, X[10], 11)
       ee, bb = GG(ee, aa, bb, cc, dd, X[ 6],  9)
       dd, aa = GG(dd, ee, aa, bb, cc, X[15],  7)
       cc, ee = GG(cc, dd, ee, aa, bb, X[ 3], 15)
       bb, dd = GG(bb, cc, dd, ee, aa, X[12],  7)
       aa, cc = GG(aa, bb, cc, dd, ee, X[ 0], 12)
       ee, bb = GG(ee, aa, bb, cc, dd, X[ 9], 15)
       dd, aa = GG(dd, ee, aa, bb, cc, X[ 5],  9)
       cc, ee = GG(cc, dd, ee, aa, bb, X[ 2], 11)
       bb, dd = GG(bb, cc, dd, ee, aa, X[14],  7)
       aa, cc = GG(aa, bb, cc, dd, ee, X[11], 13)
       ee, bb = GG(ee, aa, bb, cc, dd, X[ 8], 12)

       # /* round 3 */
       dd, aa = HH(dd, ee, aa, bb, cc, X[ 3], 11)
       cc, ee = HH(cc, dd, ee, aa, bb, X[10], 13)
       bb, dd = HH(bb, cc, dd, ee, aa, X[14],  6)
       aa, cc = HH(aa, bb, cc, dd, ee, X[ 4],  7)
       ee, bb = HH(ee, aa, bb, cc, dd, X[ 9], 14)
       dd, aa = HH(dd, ee, aa, bb, cc, X[15],  9)
       cc, ee = HH(cc, dd, ee, aa, bb, X[ 8], 13)
       bb, dd = HH(bb, cc, dd, ee, aa, X[ 1], 15)
       aa, cc = HH(aa, bb, cc, dd, ee, X[ 2], 14)
       ee, bb = HH(ee, aa, bb, cc, dd, X[ 7],  8)
       dd, aa = HH(dd, ee, aa, bb, cc, X[ 0], 13)
       cc, ee = HH(cc, dd, ee, aa, bb, X[ 6],  6)
       bb, dd = HH(bb, cc, dd, ee, aa, X[13],  5)
       aa, cc = HH(aa, bb, cc, dd, ee, X[11], 12)
       ee, bb = HH(ee, aa, bb, cc, dd, X[ 5],  7)
       dd, aa = HH(dd, ee, aa, bb, cc, X[12],  5)

       # /* round 4 */
       cc, ee = II(cc, dd, ee, aa, bb, X[ 1], 11)
       bb, dd = II(bb, cc, dd, ee, aa, X[ 9], 12)
       aa, cc = II(aa, bb, cc, dd, ee, X[11], 14)
       ee, bb = II(ee, aa, bb, cc, dd, X[10], 15)
       dd, aa = II(dd, ee, aa, bb, cc, X[ 0], 14)
       cc, ee = II(cc, dd, ee, aa, bb, X[ 8], 15)
       bb, dd = II(bb, cc, dd, ee, aa, X[12],  9)
       aa, cc = II(aa, bb, cc, dd, ee, X[ 4],  8)
       ee, bb = II(ee, aa, bb, cc, dd, X[13],  9)
       dd, aa = II(dd, ee, aa, bb, cc, X[ 3], 14)
       cc, ee = II(cc, dd, ee, aa, bb, X[ 7],  5)
       bb, dd = II(bb, cc, dd, ee, aa, X[15],  6)
       aa, cc = II(aa, bb, cc, dd, ee, X[14],  8)
       ee, bb = II(ee, aa, bb, cc, dd, X[ 5],  6)
       dd, aa = II(dd, ee, aa, bb, cc, X[ 6],  5)
       cc, ee = II(cc, dd, ee, aa, bb, X[ 2], 12)
	   
       # /* round 5 */
       bb, dd = JJ(bb, cc, dd, ee, aa, X[ 4],  9)
       aa, cc = JJ(aa, bb, cc, dd, ee, X[ 0], 15)
       ee, bb = JJ(ee, aa, bb, cc, dd, X[ 5],  5)
       dd, aa = JJ(dd, ee, aa, bb, cc, X[ 9], 11)
       cc, ee = JJ(cc, dd, ee, aa, bb, X[ 7],  6)
       bb, dd = JJ(bb, cc, dd, ee, aa, X[12],  8)
       aa, cc = JJ(aa, bb, cc, dd, ee, X[ 2], 13)
       ee, bb = JJ(ee, aa, bb, cc, dd, X[10], 12)
       dd, aa = JJ(dd, ee, aa, bb, cc, X[14],  5)
       cc, ee = JJ(cc, dd, ee, aa, bb, X[ 1], 12)
       bb, dd = JJ(bb, cc, dd, ee, aa, X[ 3], 13)
       aa, cc = JJ(aa, bb, cc, dd, ee, X[ 8], 14)
       ee, bb = JJ(ee, aa, bb, cc, dd, X[11], 11)
       dd, aa = JJ(dd, ee, aa, bb, cc, X[ 6],  8)
       cc, ee = JJ(cc, dd, ee, aa, bb, X[15],  5)
       bb, dd = JJ(bb, cc, dd, ee, aa, X[13],  6)

	   #/* parallel round 1 */
       aaa, ccc = JJJ(aaa, bbb, ccc, ddd, eee, X[ 5],  8)
       eee, bbb = JJJ(eee, aaa, bbb, ccc, ddd, X[14],  9)
       ddd, aaa = JJJ(ddd, eee, aaa, bbb, ccc, X[ 7],  9)
       ccc, eee = JJJ(ccc, ddd, eee, aaa, bbb, X[ 0], 11)
       bbb, ddd = JJJ(bbb, ccc, ddd, eee, aaa, X[ 9], 13)
       aaa, ccc = JJJ(aaa, bbb, ccc, ddd, eee, X[ 2], 15)
       eee, bbb = JJJ(eee, aaa, bbb, ccc, ddd, X[11], 15)
       ddd, aaa = JJJ(ddd, eee, aaa, bbb, ccc, X[ 4],  5)
       ccc, eee = JJJ(ccc, ddd, eee, aaa, bbb, X[13],  7)
       bbb, ddd = JJJ(bbb, ccc, ddd, eee, aaa, X[ 6],  7)
       aaa, ccc = JJJ(aaa, bbb, ccc, ddd, eee, X[15],  8)
       eee, bbb = JJJ(eee, aaa, bbb, ccc, ddd, X[ 8], 11)
       ddd, aaa = JJJ(ddd, eee, aaa, bbb, ccc, X[ 1], 14)
       ccc, eee = JJJ(ccc, ddd, eee, aaa, bbb, X[10], 14)
       bbb, ddd = JJJ(bbb, ccc, ddd, eee, aaa, X[ 3], 12)
       aaa, ccc = JJJ(aaa, bbb, ccc, ddd, eee, X[12],  6)
	   
       # /* parallel round 2 */
       eee, bbb = III(eee, aaa, bbb, ccc, ddd, X[ 6],  9)
       ddd, aaa = III(ddd, eee, aaa, bbb, ccc, X[11], 13)
       ccc, eee = III(ccc, ddd, eee, aaa, bbb, X[ 3], 15)
       bbb, ddd = III(bbb, ccc, ddd, eee, aaa, X[ 7],  7)
       aaa, ccc = III(aaa, bbb, ccc, ddd, eee, X[ 0], 12)
       eee, bbb = III(eee, aaa, bbb, ccc, ddd, X[13],  8)
       ddd, aaa = III(ddd, eee, aaa, bbb, ccc, X[ 5],  9)
       ccc, eee = III(ccc, ddd, eee, aaa, bbb, X[10], 11)
       bbb, ddd = III(bbb, ccc, ddd, eee, aaa, X[14],  7)
       aaa, ccc = III(aaa, bbb, ccc, ddd, eee, X[15],  7)
       eee, bbb = III(eee, aaa, bbb, ccc, ddd, X[ 8], 12)
       ddd, aaa = III(ddd, eee, aaa, bbb, ccc, X[12],  7)
       ccc, eee = III(ccc, ddd, eee, aaa, bbb, X[ 4],  6)
       bbb, ddd = III(bbb, ccc, ddd, eee, aaa, X[ 9], 15)
       aaa, ccc = III(aaa, bbb, ccc, ddd, eee, X[ 1], 13)
       eee, bbb = III(eee, aaa, bbb, ccc, ddd, X[ 2], 11)

       # /* parallel round 3 */
       ddd, aaa = HHH(ddd, eee, aaa, bbb, ccc, X[15],  9)
       ccc, eee = HHH(ccc, ddd, eee, aaa, bbb, X[ 5],  7)
       bbb, ddd = HHH(bbb, ccc, ddd, eee, aaa, X[ 1], 15)
       aaa, ccc = HHH(aaa, bbb, ccc, ddd, eee, X[ 3], 11)
       eee, bbb = HHH(eee, aaa, bbb, ccc, ddd, X[ 7],  8)
       ddd, aaa = HHH(ddd, eee, aaa, bbb, ccc, X[14],  6)
       ccc, eee = HHH(ccc, ddd, eee, aaa, bbb, X[ 6],  6)
       bbb, ddd = HHH(bbb, ccc, ddd, eee, aaa, X[ 9], 14)
       aaa, ccc = HHH(aaa, bbb, ccc, ddd, eee, X[11], 12)
       eee, bbb = HHH(eee, aaa, bbb, ccc, ddd, X[ 8], 13)
       ddd, aaa = HHH(ddd, eee, aaa, bbb, ccc, X[12],  5)
       ccc, eee = HHH(ccc, ddd, eee, aaa, bbb, X[ 2], 14)
       bbb, ddd = HHH(bbb, ccc, ddd, eee, aaa, X[10], 13)
       aaa, ccc = HHH(aaa, bbb, ccc, ddd, eee, X[ 0], 13)
       eee, bbb = HHH(eee, aaa, bbb, ccc, ddd, X[ 4],  7)
       ddd, aaa = HHH(ddd, eee, aaa, bbb, ccc, X[13],  5)

       # /* parallel round 4 */
       ccc, eee = GGG(ccc, ddd, eee, aaa, bbb, X[ 8], 15)
       bbb, ddd = GGG(bbb, ccc, ddd, eee, aaa, X[ 6],  5)
       aaa, ccc = GGG(aaa, bbb, ccc, ddd, eee, X[ 4],  8)
       eee, bbb = GGG(eee, aaa, bbb, ccc, ddd, X[ 1], 11)
       ddd, aaa = GGG(ddd, eee, aaa, bbb, ccc, X[ 3], 14)
       ccc, eee = GGG(ccc, ddd, eee, aaa, bbb, X[11], 14)
       bbb, ddd = GGG(bbb, ccc, ddd, eee, aaa, X[15],  6)
       aaa, ccc = GGG(aaa, bbb, ccc, ddd, eee, X[ 0], 14)
       eee, bbb = GGG(eee, aaa, bbb, ccc, ddd, X[ 5],  6)
       ddd, aaa = GGG(ddd, eee, aaa, bbb, ccc, X[12],  9)
       ccc, eee = GGG(ccc, ddd, eee, aaa, bbb, X[ 2], 12)
       bbb, ddd = GGG(bbb, ccc, ddd, eee, aaa, X[13],  9)
       aaa, ccc = GGG(aaa, bbb, ccc, ddd, eee, X[ 9], 12)
       eee, bbb = GGG(eee, aaa, bbb, ccc, ddd, X[ 7],  5)
       ddd, aaa = GGG(ddd, eee, aaa, bbb, ccc, X[10], 15)
       ccc, eee = GGG(ccc, ddd, eee, aaa, bbb, X[14],  8)

       # /* parallel round 5 */
       bbb, ddd = FFF(bbb, ccc, ddd, eee, aaa, X[12] ,  8)
       aaa, ccc = FFF(aaa, bbb, ccc, ddd, eee, X[15] ,  5)
       eee, bbb = FFF(eee, aaa, bbb, ccc, ddd, X[10] , 12)
       ddd, aaa = FFF(ddd, eee, aaa, bbb, ccc, X[ 4] ,  9)
       ccc, eee = FFF(ccc, ddd, eee, aaa, bbb, X[ 1] , 12)
       bbb, ddd = FFF(bbb, ccc, ddd, eee, aaa, X[ 5] ,  5)
       aaa, ccc = FFF(aaa, bbb, ccc, ddd, eee, X[ 8] , 14)
       eee, bbb = FFF(eee, aaa, bbb, ccc, ddd, X[ 7] ,  6)
       ddd, aaa = FFF(ddd, eee, aaa, bbb, ccc, X[ 6] ,  8)
       ccc, eee = FFF(ccc, ddd, eee, aaa, bbb, X[ 2] , 13)
       bbb, ddd = FFF(bbb, ccc, ddd, eee, aaa, X[13] ,  6)
       aaa, ccc = FFF(aaa, bbb, ccc, ddd, eee, X[14] ,  5)
       eee, bbb = FFF(eee, aaa, bbb, ccc, ddd, X[ 0] , 15)
       ddd, aaa = FFF(ddd, eee, aaa, bbb, ccc, X[ 3] , 13)
       ccc, eee = FFF(ccc, ddd, eee, aaa, bbb, X[ 9] , 11)
       bbb, ddd = FFF(bbb, ccc, ddd, eee, aaa, X[11] , 11)
       #/* combine results */
       ddd += cc + self.state[1]               
       self.state[1] = (self.state[2] + dd + eee) & 0xffffffff
       self.state[2] = (self.state[3] + ee + aaa) & 0xffffffff
       self.state[3] = (self.state[4] + aa + bbb) & 0xffffffff
       self.state[4] = (self.state[0] + bb + ccc) & 0xffffffff
       self.state[0] = ddd & 0xffffffff
       # for i in range(4):
       #    print(f'state[{i}] = %x'%self.state[i])


    def rmd160_update(self,data,ilen):
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
            self.rmd160_compress(self.buf)
            used += fill
            ilen -= fill
            left = 0

        while ilen >= 64 :
            self.rmd160_compress(data[used:used+64])
            used += 64
            ilen -= 64

        if ilen > 0:
            # print('ilen=',ilen,'used=',used)
            for i in range(ilen):
                self.buf[left+i] = data[used+i]

    def rmd160_finish(self):
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
        self.rmd160_update(padding[0:padn], padn)
        # 处理8字节长度字段
        self.rmd160_update(msglen, 8)
        c = []
        for i in range(5):
            c.append(self.state[i] & 0x000000ff)
            c.append((self.state[i] & 0x0000ff00) >> 8)
            c.append((self.state[i] & 0x00ff0000) >> 16)
            c.append((self.state[i] & 0xff000000) >> 24)
        return c

    def rmd160_hash(self, data, ilen):
       self.rmd160_update(data, ilen)
       hash = self.rmd160_finish()
       return hash


def byte2hex(msg):  # byte数组转换成16进制字符串
    ml = len(msg)
    hexstr = ""
    for i in range(ml):
       hexstr = hexstr + ('%02x' % msg[i])
    return hexstr

if __name__ == '__main__':
    print('RMD160摘要算法测试')
    str = ''
    data = list(map(lambda x: ord(x), str))
    print(data,len(data))
    a = RMD160()
    hash =a.rmd160_hash(data, len(data))
    print("摘要值:", end='')
    print(byte2hex(hash))
    print('-----------------------')
    str = 'a'
    data = list(map(lambda x: ord(x), str))
    print(data,len(data))
    a = RMD160()
    hash =a.rmd160_hash(data, len(data))
    print("摘要值:", end='')
    print(byte2hex(hash))
    print('-----------------------')
    str = 'abc'
    data = list(map(lambda x: ord(x), str))
    print(data,len(data))
    a = RMD160()
    hash =a.rmd160_hash(data, len(data))
    print("摘要值:", end='')
    print(byte2hex(hash))
    print('-----------------------')
    str = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
    data = list(map(lambda x: ord(x), str))
    print(data,len(data))
    a = RMD160()
    hash =a.rmd160_hash(data, len(data))
    print("摘要值:", end='')
    print(byte2hex(hash))
    #print_bytes_hex(hash)

        