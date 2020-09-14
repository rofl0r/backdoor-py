# -*- coding: utf-8 -*-

"""

taken from
https://github.com/jfindlay/pure_pynacl


                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

"""

import sys
import os
from array import array

if sys.version_info < (2, 6):
    raise NotImplementedError('pure_pynacl requires python-2.6 or later')

lt_py3 = sys.version_info < (3,)
lt_py33 = sys.version_info < (3, 3)

integer = long if lt_py3 else int

# "constants"
crypto_auth_hmacsha512256_tweet_BYTES = 32
crypto_auth_hmacsha512256_tweet_KEYBYTES = 32
crypto_box_curve25519xsalsa20poly1305_tweet_PUBLICKEYBYTES = 32
crypto_box_curve25519xsalsa20poly1305_tweet_SECRETKEYBYTES = 32
crypto_box_curve25519xsalsa20poly1305_tweet_BEFORENMBYTES = 32
crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES = 24
crypto_box_curve25519xsalsa20poly1305_tweet_ZEROBYTES = 32
crypto_box_curve25519xsalsa20poly1305_tweet_BOXZEROBYTES = 16
crypto_core_salsa20_tweet_OUTPUTBYTES = 64
crypto_core_salsa20_tweet_INPUTBYTES = 16
crypto_core_salsa20_tweet_KEYBYTES = 32
crypto_core_salsa20_tweet_CONSTBYTES = 16
crypto_core_hsalsa20_tweet_OUTPUTBYTES = 32
crypto_core_hsalsa20_tweet_INPUTBYTES = 16
crypto_core_hsalsa20_tweet_KEYBYTES = 32
crypto_core_hsalsa20_tweet_CONSTBYTES = 16
crypto_hashblocks_sha512_tweet_STATEBYTES = 64
crypto_hashblocks_sha512_tweet_BLOCKBYTES = 128
crypto_hashblocks_sha256_tweet_STATEBYTES = 32
crypto_hashblocks_sha256_tweet_BLOCKBYTES = 64
crypto_hash_sha512_tweet_BYTES = 64
crypto_hash_sha256_tweet_BYTES = 32
crypto_onetimeauth_poly1305_tweet_BYTES = 16
crypto_onetimeauth_poly1305_tweet_KEYBYTES = 32
crypto_scalarmult_curve25519_tweet_BYTES = 32
crypto_scalarmult_curve25519_tweet_SCALARBYTES = 32
crypto_secretbox_xsalsa20poly1305_tweet_KEYBYTES = 32
crypto_secretbox_xsalsa20poly1305_tweet_NONCEBYTES = 24
crypto_secretbox_xsalsa20poly1305_tweet_ZEROBYTES = 32
crypto_secretbox_xsalsa20poly1305_tweet_BOXZEROBYTES = 16
crypto_sign_ed25519_tweet_BYTES = 64
crypto_sign_ed25519_tweet_PUBLICKEYBYTES = 32
crypto_sign_ed25519_tweet_SECRETKEYBYTES = 64
crypto_stream_xsalsa20_tweet_KEYBYTES = 32
crypto_stream_xsalsa20_tweet_NONCEBYTES = 24
crypto_stream_salsa20_tweet_KEYBYTES = 32
crypto_stream_salsa20_tweet_NONCEBYTES = 8
crypto_verify_16_tweet_BYTES = 16
crypto_verify_32_tweet_BYTES = 32

class TypeEnum(object):
    '''
    order types used by pure_py(tweet)nacl for rapid type promotion
    '''
    u8 = 1
    u32 = 2
    u64 = 3
    Int = 5
    i64 = 7
    integer = 11


class Int(integer):
    '''
    int types
    '''
    bits = array('i').itemsize*8
    mask = (1 << bits - 1) - 1
    signed = True
    order = TypeEnum.Int

    def __str__(self):
        return integer.__str__(self)

    def __repr__(self):
        return 'Int(%s)' % integer.__repr__(self)

    def __new__(self, val=0):
        '''
        ensure that new instances have the correct size and sign
        '''
        if val < 0:
            residue = integer(-val) & self.mask
            if self.signed:
                residue = -residue
        else:
            residue = integer(val) & self.mask
        return integer.__new__(self, residue)

    def __promote_type(self, other, result):
        '''
        determine the largest type from those in self and other; if result is
        negative and both self and other are unsigned, promote it to the least
        signed type
        '''
        self_order = self.order
        other_order = other.order if isinstance(other, Int) else TypeEnum.integer

        if result < 0 and self_order < 5 and other_order < 5:
            return Int
        return self.__class__ if self_order > other_order else other.__class__

    def __unary_typed(oper):
        '''
        return a function that redefines the operation oper such that the
        result conforms to the type of self
        '''
        def operate(self):
            '''
            type the result to self
            '''
            return self.__class__(oper(self))
        return operate

    def __typed(oper):
        '''
        return a function that redefines the operation oper such that the
        result conforms to the type of self or other, whichever is larger if
        both are strongly typed (have a bits attribute); otherwise return the
        result conforming to the type of self
        '''
        def operate(self, other):
            '''
            type and bitmask the result to either self or other, whichever is
            larger
            '''
            result = oper(self, other)
            return self.__promote_type(other, result)(result)
        return operate

    def __shift(oper):
        '''
        return a function that performs bit shifting, but preserves the type of
        the left value
        '''
        def operate(self, other):
            '''
            emulate C bit shifting
            '''
            return self.__class__(oper(self, other))
        return operate

    def __invert():
        '''
        return a function that performs bit inversion
        '''
        def operate(self):
            '''
            emulate C bit inversion
            '''
            if self.signed:
                return self.__class__(integer.__invert__(self))
            else:
                return self.__class__(integer.__xor__(self, self.mask))
        return operate

    # bitwise operations
    __lshift__  = __shift(integer.__lshift__)
    __rlshift__ = __shift(integer.__rlshift__)
    __rshift__  = __shift(integer.__rshift__)
    __rrshift__ = __shift(integer.__rrshift__)
    __and__     = __typed(integer.__and__)
    __rand__    = __typed(integer.__rand__)
    __or__      = __typed(integer.__or__)
    __ror__     = __typed(integer.__ror__)
    __xor__     = __typed(integer.__xor__)
    __rxor__    = __typed(integer.__rxor__)
    __invert__  = __invert()

    # arithmetic operations
    if not lt_py3:
        __ceil__  = __unary_typed(integer.__ceil__)
        __floor__ = __unary_typed(integer.__floor__)
        __int__   = __unary_typed(integer.__int__)
    __abs__       = __unary_typed(integer.__abs__)
    __pos__       = __unary_typed(integer.__pos__)
    __neg__       = __unary_typed(integer.__neg__)
    __add__       = __typed(integer.__add__)
    __radd__      = __typed(integer.__radd__)
    __sub__       = __typed(integer.__sub__)
    __rsub__      = __typed(integer.__rsub__)
    __mod__       = __typed(integer.__mod__)
    __rmod__      = __typed(integer.__rmod__)
    __mul__       = __typed(integer.__mul__)
    __rmul__      = __typed(integer.__rmul__)
    if lt_py3:
        __div__   = __typed(integer.__div__)
        __rdiv__  = __typed(integer.__rdiv__)
    __floordiv__  = __typed(integer.__floordiv__)
    __rfloordiv__ = __typed(integer.__rfloordiv__)
    __pow__       = __typed(integer.__pow__)
    __rpow__      = __typed(integer.__rpow__)


class IntArray(list):
    '''
    arrays of int types
    '''
    def __init__(self, typ, init=(), size=0):
        '''
        create array of ints
        '''
        self.typ = typ

        if lt_py3 and isinstance(init, bytes):
            init = [ord(i) for i in init]

        if size:
            init_size = len(init)
            if init_size < size:
                list.__init__(self, [typ(i) for i in init] + [typ() for i in range(size - init_size)])
            else:
                list.__init__(self, [typ(i) for i in init[:size]])
        else:
            list.__init__(self, [typ(i) for i in init])

    def __str__(self):
        return list.__str__(self)

    def __repr__(self):
        return 'IntArray(%s, init=%s)' % (self.typ, list.__repr__(self))

class u8(Int):
    '''unsigned char'''
    bits = array('B').itemsize*8
    mask = (1 << bits) - 1
    signed = False
    order = TypeEnum.u8

    def __repr__(self):
        return 'u8(%s)' % integer.__repr__(self)


class u32(Int):
    '''unsigned long'''
    bits = array('L').itemsize*8
    mask = (1 << bits) - 1
    signed = False
    order = TypeEnum.u32

    def __repr__(self):
        return 'u32(%s)' % integer.__repr__(self)


class u64(Int):
    '''unsigned long long'''
    bits = array('L' if lt_py33 else 'Q').itemsize*8
    mask = (1 << bits) - 1
    signed = False
    order = TypeEnum.u64

    def __repr__(self):
        return 'u64(%s)' % integer.__repr__(self)


class i64(Int):
    '''long long'''
    bits = array('l' if lt_py33 else 'q').itemsize*8
    mask = (1 << bits - 1) - 1
    signed = True
    order = TypeEnum.i64

    def __repr__(self):
        return 'i64(%s)' % integer.__repr__(self)


class gf(IntArray):
    def __init__(self, init=()):
        IntArray.__init__(self, i64, init=init, size=16)


def randombytes(c, s):
    '''
    insert s random bytes into c
    '''
    if lt_py3:
        c[:s] = bytearray(os.urandom(s))
    else:
        c[:s] = os.urandom(s)


_0 = IntArray(u8, size=16)
_9 = IntArray(u8, size=32, init=[9])

gf0 = gf()
gf1 = gf([1])
_121665 = gf([0xDB41, 1])
D = gf([0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203])
D2 = gf([0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406])
X = gf([0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169])
Y = gf([0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666])
I = gf([0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83])


def L32(x, c):
    '''static u32 L32(u32 x, int c)'''
    return (u32(x) << c) | ((u32(x) & 0xffffffff) >> (32 - c))


def ld32(x):
    '''u32 ld32(const u8*x)'''
    u = u32(x[3])
    u = (u << 8) | u32(x[2])
    u = (u << 8) | u32(x[1])
    return (u << 8) | u32(x[0])


def dl64(x):
    '''u64 dl64(const u8*x)'''
    u = u64()
    for i in range(8): u = (u << 8) | u8(x[i])
    return u


def st32(x, u):
    '''void st32(u8*x, u32 u)'''
    for i in range(4): x[i] = u8(u); u >>= 8
    return x


def ts64(x, u):
    '''void ts64(u8*x, u64 u)'''
    for i in range(7, -1, -1): x[i] = u8(u); u >>= 8
    return x


def vn(x, y, n):
    '''int vn(const u8*x, const u8*y, int n)'''
    d = u32()
    for i in range(n): d |= x[i] ^ y[i]
    return (1 & ((d - 1) >> 8)) - 1


def crypto_verify_16_tweet(x, y):
    '''int crypto_verify_16_tweet(const u8*x, const u8*y)'''
    return vn(x, y, 16)


def crypto_verify_32_tweet(x, y):
    '''int crypto_verify_32_tweet(const u8*x, const u8*y)'''
    return vn(x, y, 32)


def core(out, in_, k, c, h):
    '''void core(u8*out, const u8*in, const u8*k, const u8*c, int h)'''
    w = IntArray(u32, size=16)
    x = IntArray(u32, size=16)
    y = IntArray(u32, size=16)
    t = IntArray(u32, size=4)

    for i in range(4):
        x[5*i] = ld32(c[4*i:])
        x[1 + i] = ld32(k[4*i:])
        x[6 + i] = ld32(in_[4*i:])
        x[11 + i] = ld32(k[16 + 4*i:])

    for i in range(16): y[i] = x[i]

    for i in range(20):
        for j in range(4):
            for m in range(4): t[m] = x[(5*j + 4*m)%16]
            t[1] ^= L32(t[0] + t[3], 7)
            t[2] ^= L32(t[1] + t[0], 9)
            t[3] ^= L32(t[2] + t[1],13)
            t[0] ^= L32(t[3] + t[2],18)
            for m in range(4): w[4*j + (j + m)%4] = t[m]
        for m in range(16): x[m] = w[m]

    if h:
        for i in range(16): x[i] += y[i]
        for i in range(4):
            x[5*i] -= ld32(c[4*i:])
            x[6+i] -= ld32(in_[4*i:])
        for i in range(4):
            out[4*i:] = st32(out[4*i:], x[5*i])
            out[16 + 4*i:] = st32(out[16 + 4*i:], x[6 + i])
    else:
        for i in range(16):
            out[4*i:] = st32(out[4*i:], x[i] + y[i])


def crypto_core_salsa20_tweet(out, in_, k, c):
    '''int crypto_core_salsa20_tweet(u8*out, const u8*in, const u8*k, const u8*c)'''
    core(out, in_, k, c, False)
    return 0


def crypto_core_hsalsa20_tweet(out, in_, k, c):
    '''int crypto_core_hsalsa20_tweet(u8*out, const u8*in, const u8*k, const u8*c)'''
    core(out, in_, k, c, True)
    return 0


sigma = IntArray(u8, size=16, init=b'expand 32-byte k')


def crypto_stream_salsa20_tweet_xor(c, m, b, n, k):
    '''int crypto_stream_salsa20_tweet_xor(u8*c, const u8*m, u64 b, const u8*n, const u8*k)'''
    z = IntArray(u8, size=16)
    x = IntArray(u8, size=64)

    if not b: return 0

    for i in range(8): z[i] = n[i]

    c_off = 0 ; m_off = 0
    while b >= 64:
        crypto_core_salsa20_tweet(x, z, k, sigma)
        for i in range(64): c[i + c_off] = (m[i + m_off] if m else 0) ^ x[i]
        u = u32(1)
        for i in range(8, 16):
            u += u32(z[i])
            z[i] = u
            u >>= 8
        b -= 64
        c_off += 64
        if m: m_off += 64

    if b:
        crypto_core_salsa20_tweet(x, z, k, sigma)
        for i in range(b): c[i + c_off] = (m[i + m_off] if m else 0) ^ x[i]

    return 0


def crypto_stream_salsa20_tweet(c, d, n, k):
    '''int crypto_stream_salsa20_tweet(u8*c, u64 d, const u8*n, const u8*k)'''
    return crypto_stream_salsa20_tweet_xor(c, IntArray(u8), d, n, k)


def crypto_stream_xsalsa20_tweet(c, d, n, k):
    '''int crypto_stream_xsalsa20_tweet(u8*c, u64 d, const u8*n, const u8*k)'''
    s = IntArray(u8, size=32)
    crypto_core_hsalsa20_tweet(s, n, k, sigma)
    return crypto_stream_salsa20_tweet(c, d, n[16:], s)


def crypto_stream_xsalsa20_tweet_xor(c, m, d, n, k):
    '''int crypto_stream_xsalsa20_tweet_xor(u8*c, const u8*m, u64 d, const u8*n, const u8*k)'''
    s = IntArray(u8, size=32)
    crypto_core_hsalsa20_tweet(s, n, k, sigma)
    return crypto_stream_salsa20_tweet_xor(c, m, d, n[16:], s)


def add1305(h, c):
    '''void add1305(u32*h, const u32*c)'''
    u = u32()
    for j in range(17):
        u += u32(h[j] + c[j])
        h[j] = u & 255
        u >>= 8


minusp = IntArray(u32, size=17, init=(5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252))


def crypto_onetimeauth_poly1305_tweet(out, m, n, k):
    '''int crypto_onetimeauth_poly1305_tweet(u8*out, const u8*m, u64 n, const u8*k)'''
    s = u32()
    u = u32()
    x = IntArray(u32, size=17)
    r = IntArray(u32, size=17)
    h = IntArray(u32, size=17)
    c = IntArray(u32, size=17)
    g = IntArray(u32, size=17)

    for j in range(16): r[j] = k[j]
    r[3] &= 15
    r[4] &= 252
    r[7] &= 15
    r[8] &= 252
    r[11] &= 15
    r[12] &= 252
    r[15] &= 15

    while n > 0:
        c[:17] = 17*[u32()]
        for j in range(16):
            if j >= n: j -= 1 ; break
            c[j] = m[j]
        j += 1
        c[j] = 1
        m = m[j:]; n -= j
        add1305(h, c)

        for i in range(17):
            x[i] = 0
            for j in range(17): x[i] += h[j]*(r[i - j] if j <= i else 320*r[i + 17 - j])

        for i in range(17): h[i] = x[i]
        u = 0

        for j in range(16):
            u += h[j]
            h[j] = u & 255
            u >>= 8

        u += h[16]; h[16] = u & 3
        u = 5*(u >> 2)

        for j in range(16):
            u += h[j]
            h[j] = u & 255
            u >>= 8

        u += h[16]; h[16] = u

    for j in range(17): g[j] = h[j]
    add1305(h, minusp)
    s = -(h[16] >> 7)
    for j in range(17): h[j] ^= s & (g[j] ^ h[j])

    for j in range(16): c[j] = k[j + 16]
    c[16] = 0
    add1305(h, c)
    for j in range(16): out[j] = h[j]

    return 0


def crypto_onetimeauth_poly1305_tweet_verify(h, m, n, k):
    '''int crypto_onetimeauth_poly1305_tweet_verify(const u8*h, const u8*m, u64 n, const u8*k)'''
    x = IntArray(u8, size=16)
    crypto_onetimeauth_poly1305_tweet(x, m, n, k)
    return crypto_verify_16_tweet(h, x)


def crypto_secretbox_xsalsa20poly1305_tweet(c, m, d, n, k):
    '''int crypto_secretbox_xsalsa20poly1305_tweet(u8*c, const u8*m, u64 d, const u8*n, const u8*k)'''
    if d < 32: return -1
    crypto_stream_xsalsa20_tweet_xor(c, m, d, n, k)
    c_out = c[16:]
    crypto_onetimeauth_poly1305_tweet(c_out, c[32:], d - 32, c)
    c[16:] = c_out
    c[:16] = 16*[u8()]
    return 0


def crypto_secretbox_xsalsa20poly1305_tweet_open(m, c, d, n, k):
    '''int crypto_secretbox_xsalsa20poly1305_tweet_open(u8*m, const u8*c, u64 d, const u8*n, const u8*k)'''
    x = IntArray(u8, size=32)
    if d < 32: return -1
    crypto_stream_xsalsa20_tweet(x, 32, n, k)
    if crypto_onetimeauth_poly1305_tweet_verify(c[16:], c[32:], d - 32, x) != 0: return -1
    crypto_stream_xsalsa20_tweet_xor(m, c, d, n, k)
    m[:32] = 32*[u8()]
    return 0


def set25519(r, a):
    '''void set25519(gf r, const gf a)'''
    for i in range(16): r[i] = a[i]


def car25519(o):
    '''void car25519(gf o)'''
    c = i64()
    for i in range(16):
        o[i] += (i64(1) << 16)
        c = o[i] >> 16
        o[(i + 1)*(i < 15)] += c - 1 + 37*(c - 1)*(i == 15)
        o[i] -= c << 16


def sel25519(p, q, b):
    '''void sel25519(gf p, gf q, int b)'''
    t = i64()
    c = i64(~(b - 1))
    for i in range(16):
        t = c & (p[i] ^ q[i])
        p[i] ^= t
        q[i] ^= t
    return p, q


def pack25519(o, n):
    '''void pack25519(u8*o, const gf n)'''
    b = int()
    m = gf()
    t = gf()
    for i in range(16): t[i] = n[i]

    car25519(t)
    car25519(t)
    car25519(t)

    for j in range(2):
        m[0] = t[0] - 0xffed
        for i in range(1,15):
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1)
            m[i-1] &= 0xffff

        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1)
        b = (m[15] >> 16) & 1
        m[14] &= 0xffff

        sel25519(t, m, 1 - b)

    for i in range(16):
        o[2*i] = t[i] & 0xff
        o[2*i + 1] = t[i] >> 8


def neq25519(a, b):
    '''int neq25519(const gf a, const gf b)'''
    c = IntArray(u8, size=32)
    d = IntArray(u8, size=32)
    pack25519(c, a)
    pack25519(d, b)
    return crypto_verify_32_tweet(c, d)


def par25519(a):
    '''u8 par25519(const gf a)'''
    d = IntArray(u8, size=32)
    pack25519(d, a)
    return d[0] & 1


def unpack25519(o, n):
    '''void unpack25519(gf o, const u8*n)'''
    for i in range(16): o[i] = n[2*i] + (i64(n[2*i + 1]) << 8)
    o[15] &= 0x7fff


def A(o, a, b):
    '''void A(gf o, const gf a, const gf b)'''
    for i in range(16): o[i] = a[i] + b[i]


def Z(o, a, b):
    '''void Z(gf o, const gf a, const gf b)'''
    for i in range(16): o[i] = a[i] - b[i]


def M(o, a, b):
    '''void M(gf o, const gf a, const gf b)'''
    t = IntArray(i64, size=31)
    for i in range(16):
        for j in range(16): t[i + j] += a[i]*b[j]
    for i in range(15): t[i] += 38*t[i + 16]
    for i in range(16): o[i] = t[i]

    car25519(o)
    car25519(o)

    return o


def S(o, a):
    '''void S(gf o, const gf a)'''
    M(o, a, a)


def inv25519(o, i):
    '''void inv25519(gf o, const gf i)'''
    c = gf()
    for a in range(16): c[a] = i[a]
    for a in range(253, -1, -1):
        S(c, c)
        if a != 2 and a != 4: M(c, c, i)

    for a in range(16): o[a] = c[a]

    return o


def pow2523(o, i):
    '''void pow2523(gf o, const gf i)'''
    c = gf()
    for a in range(16): c[a] = i[a]
    for a in range(250, -1, -1):
        S(c, c)
        if a != 1: M(c, c, i)

    for a in range(16): o[a] = c[a]


def crypto_scalarmult_curve25519_tweet(q, n, p):
    '''int crypto_scalarmult_curve25519_tweet(u8*q, const u8*n, const u8*p)'''
    z = IntArray(u8, size=32)
    x = IntArray(i64, size=80)
    r = i64()

    a = gf()
    b = gf()
    c = gf()
    d = gf()
    e = gf()
    f = gf()

    for i in range(31): z[i] = n[i]
    z[31] = (n[31] & 127) | 64
    z[0] &= 248

    unpack25519(x, p)

    for i in range(16):
        b[i] = x[i]
        d[i] = a[i] = c[i] = 0

    a[0] = d[0] = 1
    for i in range(254, -1, -1):
        r = (z[i >> 3] >> (i & 7)) & 1
        sel25519(a, b, r)
        sel25519(c, d, r)
        A(e, a, c)
        Z(a, a, c)
        A(c, b, d)
        Z(b, b, d)
        S(d, e)
        S(f, a)
        M(a, c, a)
        M(c, b, e)
        A(e, a, c)
        Z(a, a, c)
        S(b, a)
        Z(c, d, f)
        M(a, c, _121665)
        A(a, a, d)
        M(c, c, a)
        M(a, d, f)
        M(d, b, x)
        S(b, e)
        sel25519(a, b, r)
        sel25519(c, d, r)

    for i in range(16):
        x[i + 16] = a[i]
        x[i + 32] = c[i]
        x[i + 48] = b[i]
        x[i + 64] = d[i]

    x[32:] = inv25519(x[32:], x[32:])
    x[16:] = M(x[16:], x[16:], x[32:])
    pack25519(q, x[16:])
    return 0


def crypto_scalarmult_curve25519_tweet_base(q, n):
    '''int crypto_scalarmult_curve25519_tweet_base(u8*q, const u8*n)'''
    return crypto_scalarmult_curve25519_tweet(q, n, _9)


def crypto_box_curve25519xsalsa20poly1305_tweet_keypair(y, x):
    '''int crypto_box_curve25519xsalsa20poly1305_tweet_keypair(u8*y, u8*x)'''
    randombytes(x, 32)
    return crypto_scalarmult_curve25519_tweet_base(y, x)


def crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(k, y, x):
    '''int crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(u8*k, const u8*y, const u8*x)'''
    s = IntArray(u8, size=32)
    crypto_scalarmult_curve25519_tweet(s, x, y)
    return crypto_core_hsalsa20_tweet(k, _0, s, sigma)


def crypto_box_curve25519xsalsa20poly1305_tweet_afternm(c, m, d, n, k):
    '''int crypto_box_curve25519xsalsa20poly1305_tweet_afternm(u8*c, const u8*m, u64 d, const u8*n, const u8*k)'''
    return crypto_secretbox_xsalsa20poly1305_tweet(c, m, d, n, k)


def crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(m, c, d, n, k):
    '''int crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(u8*m, const u8*c, u64 d, const u8*n, const u8*k)'''
    return crypto_secretbox_xsalsa20poly1305_tweet_open(m, c, d, n, k)


def crypto_box_curve25519xsalsa20poly1305_tweet(c, m, d, n, y, x):
    '''int crypto_box_curve25519xsalsa20poly1305_tweet(u8*c, const u8*m, u64 d, const u8*n, const u8*y, const u8*x)'''
    k = IntArray(u8, size=32)
    crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(k, y, x)
    return crypto_box_curve25519xsalsa20poly1305_tweet_afternm(c, m, d, n, k)


def crypto_box_curve25519xsalsa20poly1305_tweet_open(m, c, d, n, y, x):
    '''int crypto_box_curve25519xsalsa20poly1305_tweet_open(u8*m, const u8*c, u64 d, const u8*n, const u8*y, const u8*x)'''
    k = IntArray(u8, size=32)
    crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(k, y, x)
    return crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(m, c, d, n, k)


def R(x, c):
    '''u64 R(u64 x, int c)'''
    return (u64(x) >> c) | (u64(x) << (64 - c))


def Ch(x, y, z):
    '''u64 Ch(u64 x, u64 y, u64 z)'''
    return (u64(x) & u64(y)) ^ (~u64(x) & u64(z))


def Maj(x, y, z):
    '''u64 Maj(u64 x, u64 y, u64 z)'''
    return (u64(x) & u64(y)) ^ (u64(x) & u64(z)) ^ (u64(y) & u64(z))


def Sigma0(x):
    '''u64 Sigma0(u64 x)'''
    return R(x, 28) ^ R(x, 34) ^ R(x, 39)


def Sigma1(x):
    '''u64 Sigma1(u64 x)'''
    return R(x, 14) ^ R(x, 18) ^ R(x, 41)


def sigma0(x):
    '''u64 sigma0(u64 x)'''
    return R(x, 1) ^ R(x, 8) ^ (x >> 7)


def sigma1(x):
    '''u64 sigma1(u64 x)'''
    return R(x, 19) ^ R(x, 61) ^ (x >> 6)


K = IntArray(u64, size=80, init=[
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
])


def crypto_hashblocks_sha512_tweet(x, m, n):
    '''int crypto_hashblocks_sha512_tweet(u8*x, const u8*m, u64 n)'''
    z = IntArray(u64, size=8)
    b = IntArray(u64, size=8)
    a = IntArray(u64, size=8)
    w = IntArray(u64, size=16)
    t = u64()

    for i in range(8): z[i] = a[i] = dl64(x[8*i:])

    m_off = 0
    while n >= 128:
        for i in range(16): w[i] = dl64(m[8*i + m_off:])

        for i in range(80):
            for j in range(8): b[j] = a[j]
            t = a[7] + Sigma1(a[4]) + Ch(a[4], a[5], a[6]) + K[i] + w[i%16]
            b[7] = t + Sigma0(a[0]) + Maj(a[0], a[1], a[2])
            b[3] += t

            for j in range(8): a[(j + 1)%8] = b[j]
            if i%16 == 15:
                for j in range(16):
                    w[j] += w[(j + 9)%16] + sigma0(w[(j + 1)%16]) + sigma1(w[(j + 14)%16])

        for i in range(8):
            a[i] += z[i]; z[i] = a[i]

        m_off += 128
        n -= 128

    for i in range(8): x[8*i:] = ts64(x[8*i:], z[i])

    return n


iv = IntArray(u8, size=64, init=[
    0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08,
    0xbb, 0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b,
    0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b,
    0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1,
    0x51, 0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1,
    0x9b, 0x05, 0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f,
    0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b,
    0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79
])


def crypto_hash_sha512_tweet(out, m, n):
    '''int crypto_hash_sha512_tweet(u8*out, const u8*m, u64 n)'''
    h = IntArray(u8, size=64)
    x = IntArray(u8, size=256)
    b = u64(n)

    for i in range(64): h[i] = iv[i]

    crypto_hashblocks_sha512_tweet(h, m, n)
    m_off = n
    n &= 127
    m_off -= n

    x[:256] = 256*[u8()]
    for i in range(n): x[i] = m[i + m_off]
    x[n] = 128

    n = 256 - 128*(n < 112)
    x[n - 9] = b >> 61
    x[n - 8:] = ts64(x[n - 8:], b << 3)
    crypto_hashblocks_sha512_tweet(h, x, n)

    for i in range(64): out[i] = h[i]

    return 0


def add(p, q):
    '''void add(gf p[4], gf q[4])'''
    a = gf()
    b = gf()
    c = gf()
    d = gf()
    t = gf()
    e = gf()
    f = gf()
    g = gf()
    h = gf()

    Z(a, p[1], p[0])
    Z(t, q[1], q[0])
    M(a, a, t)
    A(b, p[0], p[1])
    A(t, q[0], q[1])
    M(b, b, t)
    M(c, p[3], q[3])
    M(c, c, D2)
    M(d, p[2], q[2])
    A(d, d, d)
    Z(e, b, a)
    Z(f, d, c)
    A(g, d, c)
    A(h, b, a)

    M(p[0], e, f)
    M(p[1], h, g)
    M(p[2], g, f)
    M(p[3], e, h)


def cswap(p, q, b):
    '''void cswap(gf p[4], gf q[4], u8 b)'''
    for i in range(4):
        p[i], q[i] = sel25519(p[i], q[i], b)


def pack(r, p):
    '''void pack(u8*r, gf p[4])'''
    tx = gf()
    ty = gf()
    zi = gf()
    inv25519(zi, p[2])
    M(tx, p[0], zi)
    M(ty, p[1], zi)
    pack25519(r, ty)
    r[31] ^= par25519(tx) << 7


def scalarmult(p, q, s):
    '''void scalarmult(gf p[4], gf q[4], const u8*s)'''
    set25519(p[0], gf0)
    set25519(p[1], gf1)
    set25519(p[2], gf1)
    set25519(p[3], gf0)
    for i in range(255, -1, -1):
        b = u8((s[i//8] >> (i & 7)) & 1)
        cswap(p, q, b)
        add(q, p)
        add(p, p)
        cswap(p, q, b)


def scalarbase(p, s):
    '''void scalarbase(gf p[4], const u8*s)'''
    q = [gf() for i in range(4)]
    set25519(q[0], X)
    set25519(q[1], Y)
    set25519(q[2], gf1)
    M(q[3], X, Y)
    scalarmult(p, q, s)


def crypto_sign_ed25519_tweet_keypair(pk, sk):
    '''int crypto_sign_ed25519_tweet_keypair(u8*pk, u8*sk)'''
    d = IntArray(u8, size=64)
    p = [gf() for i in range(4)]

    randombytes(sk, 32)
    crypto_hash_sha512_tweet(d, sk, 32)
    d[0] &= 248
    d[31] &= 127
    d[31] |= 64

    scalarbase(p, d)
    pack(pk, p)

    for i in range(32): sk[32 + i] = pk[i]
    return 0


L = IntArray(u64, size=32, init=[
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
])


def modL(r, x):
    '''void modL(u8*r, i64 x[64])'''
    carry = i64()
    for i in range(63, 31, -1):
        carry = 0
        for j in range(i - 32, i - 12):
            x[j] += carry - 16*x[i]*L[j - (i - 32)]
            carry = (x[j] + 128) >> 8
            x[j] -= carry << 8
        j += 1
        x[j] += carry
        x[i] = 0

    carry = 0
    for j in range(32):
        x[j] += carry - (x[31] >> 4)*L[j]
        carry = x[j] >> 8
        x[j] &= 255

    for j in range(32): x[j] -= carry*L[j]
    for i in range(32):
        x[i + 1] += x[i] >> 8
        r[i] = x[i] & 255

    return r


def reduce(r):
    '''void reduce(u8*r)'''
    x = IntArray(i64, size=64)
    for i in range(64): x[i] = u64(r[i])
    r[:64] = 64*[u8()]
    modL(r, x)


def crypto_sign_ed25519_tweet(sm, smlen, m, n, sk):
    '''int crypto_sign_ed25519_tweet(u8*sm, u64*smlen, const u8*m, u64 n, const u8*sk)'''
    d = IntArray(u8, size=64)
    h = IntArray(u8, size=64)
    r = IntArray(u8, size=64)
    x = IntArray(i64, size=64)
    p = [gf() for i in range(4)]

    crypto_hash_sha512_tweet(d, sk, 32)
    d[0] &= 248
    d[31] &= 127
    d[31] |= 64

    # There is no (simple?) way to return this argument's value back to the
    # user in python.  Rather than redefining the return value of this function
    # it is better to advise the user that ``smlen`` does not work as it does
    # in the C implementation and that its value will be equal to ``n + 64``.
    smlen = n + 64
    for i in range(n): sm[64 + i] = m[i]
    for i in range(32): sm[32 + i] = d[32 + i]

    crypto_hash_sha512_tweet(r, sm[32:], n + 32)
    reduce(r)
    scalarbase(p, r)
    pack(sm, p)

    for i in range(32): sm[i + 32] = sk[i + 32]
    crypto_hash_sha512_tweet(h, sm, n + 64)
    reduce(h)

    for i in range(64): x[i] = 0
    for i in range(32): x[i] = u64(r[i])
    for i in range(32):
        for j in range(32): x[i + j] += h[i]*u64(d[j])
    sm[32:] = modL(sm[32:], x)

    return 0


def unpackneg(r, p):
    '''int unpackneg(gf r[4], const u8 p[32])'''
    t = gf()
    chk = gf()
    num = gf()
    den = gf()
    den2 = gf()
    den4 = gf()
    den6 = gf()

    set25519(r[2], gf1)
    unpack25519(r[1], p)
    S(num, r[1])
    M(den, num, D)
    Z(num, num, r[2])
    A(den, r[2], den)

    S(den2, den)
    S(den4, den2)
    M(den6, den4, den2)
    M(t, den6, num)
    M(t, t, den)

    pow2523(t, t)
    M(t, t, num)
    M(t, t, den)
    M(t, t, den)
    M(r[0], t, den)

    S(chk, r[0])
    M(chk, chk, den)
    if neq25519(chk, num): M(r[0], r[0], I)

    S(chk, r[0])
    M(chk, chk, den)
    if neq25519(chk, num): return -1

    if par25519(r[0]) == (p[31] >> 7): Z(r[0], gf0, r[0])

    M(r[3], r[0], r[1])
    return 0


def crypto_sign_ed25519_tweet_open(m, mlen, sm, n, pk):
    '''int crypto_sign_ed25519_tweet_open(u8*m, u64*mlen, const u8*sm, u64 n, const u8*pk)'''
    t = IntArray(u8, size=32)
    h = IntArray(u8, size=64)
    p = [gf() for i in range(4)]
    q = [gf() for i in range(4)]

    mlen = -1
    if n < 64: return -1

    if unpackneg(q, pk): return -1

    for i in range(n): m[i] = sm[i]
    for i in range(32): m[i + 32] = pk[i]
    crypto_hash_sha512_tweet(h, m, n)
    reduce(h)
    scalarmult(p, q, h)

    scalarbase(q, sm[32:])
    add(p, q)
    pack(t, p)

    n -= 64
    if crypto_verify_32_tweet(sm, t):
        for i in range(n): m[i] = 0
        return -1

    for i in range(n): m[i] = sm[i + 64]
    # There is no (simple?) way to return this argument's value back to the
    # user in python.  Rather than redefining the return value of this function
    # it is better to advise the user that ``mlen`` does not work as it does in
    # the C implementation and that its value will be equal to ``-1`` if ``n <
    # 64`` or decryption fails and ``n - 64`` otherwise.
    mlen = n
    return 0
