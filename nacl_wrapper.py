import sys

def intarrtohex(arr):
	s = ''
	for x in arr:
		c = hex(x)[2:]
		if c[-1:] == 'L': c = c[:-1]
		while len(c) < 2: c = '0' + c
		s += c
#	assert(len(s) == len(arr)*2)
	return s

def chararrtohex(arr):
	s = ''
	for x in arr:
		c = hex(ord(x))[2:]
		if c[-1:] == 'L': c = c[:-1]
		while len(c) < 2: c = '0' + c
		s += c
#	assert(len(s) == len(arr)*2)
	return s

if 1:
	import tweetnacl_pure

	PUBLICKEYBYTES = tweetnacl_pure.crypto_box_curve25519xsalsa20poly1305_tweet_PUBLICKEYBYTES
	SECRETKEYBYTES = tweetnacl_pure.crypto_box_curve25519xsalsa20poly1305_tweet_SECRETKEYBYTES
	NONCEBYTES = tweetnacl_pure.crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES
	ZEROBYTES = tweetnacl_pure.crypto_box_curve25519xsalsa20poly1305_tweet_ZEROBYTES

	nacl_keypair = tweetnacl_pure.crypto_box_curve25519xsalsa20poly1305_tweet_keypair
	nacl_box = tweetnacl_pure.crypto_box_curve25519xsalsa20poly1305_tweet
	nacl_box_open = tweetnacl_pure.crypto_box_curve25519xsalsa20poly1305_tweet_open

	arrtohex = intarrtohex

	def newarr(count):
		return tweetnacl_pure.IntArray(tweetnacl_pure.u8, size=count)

	def my_crypto_box(m, n, pk, sk):
		crypted = newarr(ZEROBYTES+len(m))
		padded = newarr(len(crypted))
		for x in range(ZEROBYTES): padded[x] = 0
		for x in range(len(m)): padded[ZEROBYTES+x] = m[x]
		ret = nacl_box(crypted, padded, len(padded), n, pk, sk)
		return ret, crypted

	def my_crypto_box_open(c, n, pk, sk):
		decrypted = newarr(len(c))
		ret = nacl_box_open(decrypted, c, len(c), n, pk, sk)
		dec_chall = decrypted[ZEROBYTES:]
		return ret, dec_chall

	def hextoarr(h):
		a = newarr(len(h)/2)
		a2 = h.decode('hex')
		for x in range(len(a2)):
			a[x] = ord(a2[x])
		return a

	def my_randombytes(a, cnt):
		tweetnacl_pure.randombytes(a, cnt)

	def gen_keypair():
		pk = newarr(PUBLICKEYBYTES)
		sk = newarr(SECRETKEYBYTES)
		nacl_keypair(pk, sk)
		return pk, sk

else:
	import tweetnacl, ctypes
	PUBLICKEYBYTES = tweetnacl.crypto_box_PUBLICKEYBYTES
	SECRETKEYBYTES = tweetnacl.crypto_box_SECRETKEYBYTES
	NONCEBYTES = tweetnacl.crypto_box_NONCEBYTES
	ZEROBYTES = tweetnacl.crypto_box_ZEROBYTES
	BOXZEROBYTES = tweetnacl.crypto_secretbox_BOXZEROBYTES

	nacl_keypair = tweetnacl.crypto_box_keypair
	nacl_box = tweetnacl.crypto_box
	nacl_box_open = tweetnacl.crypto_box_open

	def newarr(count):
		return ctypes.create_string_buffer("", size=count)

	def hextoarr(h):
		return h.decode('hex')

	def my_crypto_box(m, n, pk, sk):
		try:
			c = nacl_box(m, n, pk, sk)
			return 0, '\x00'*BOXZEROBYTES + c
		except:
			return -1, ""

	def my_crypto_box_open(c, n, pk, sk):
		try:
			m = nacl_box_open(c[BOXZEROBYTES:], n, pk, sk)
			return 0, m
		except:
			return -1, ""

	def my_randombytes(a, cnt):
		import os
		for x in range(cnt):
			a[x] = os.urandom(1)

	def arrtohex(arr):
		try:
			return arr.encode('hex')
		except AttributeError:
			return chararrtohex(arr)

	def gen_keypair():
		return tweetnacl.crypto_box_keypair()

def handshake_challenge(pk):
	challenge = newarr(NONCEBYTES)
	nonce = newarr(NONCEBYTES)
	my_randombytes(challenge, len(challenge))
	my_randombytes(nonce, len(nonce))
	return arrtohex(pk) + arrtohex(challenge) + arrtohex(nonce)

def handshake_challenge_parts(challenge):
	l1 = PUBLICKEYBYTES
	l2 = NONCEBYTES
	l3 = NONCEBYTES
	pk = hextoarr(challenge[0:(l1)*2])
	chall = hextoarr(challenge[(l1)*2:(l1+l2)*2])
	nonce = hextoarr(challenge[(l1+l2)*2:(l1+l2+l3)*2])
	return pk, chall, nonce

def handshake_response(challenge, pk, sk):
	their_pk, chall, nonce = handshake_challenge_parts(challenge)
	ret, crypted = my_crypto_box(chall, nonce, their_pk, sk)
	return ret, arrtohex(pk)+arrtohex(crypted)

def handshake_response_parts(response):
	l1 = PUBLICKEYBYTES
	l2 = ZEROBYTES
	l3 = NONCEBYTES
	pk = hextoarr(response[0:(l1)*2])
	crypted = hextoarr(response[(l1)*2:(l1+l2+l3)*2])
	return pk, crypted

def arr_equal(a1, a2):
	if len(a1) != len(a2): return False
	for x in range(len(a1)):
		if a1[x] != a2[x]: return False
	return True

def handshake_response_verify(challenge, response, authed_pk, our_sk):
	if len(response) != 2*(PUBLICKEYBYTES + ZEROBYTES + NONCEBYTES):
		return False
	our_pk, chall, nonce = handshake_challenge_parts(challenge)
	their_pk, crypted_chall = handshake_response_parts(response)
	if not arr_equal(their_pk, authed_pk): return False
	ret, decrypted = my_crypto_box_open(crypted_chall, nonce, their_pk, our_sk)
	if ret != 0: return False
	return arr_equal(decrypted, chall)


def self_test():
	"""
	challenge = newarr(NONCEBYTES)
	nonce = newarr(NONCEBYTES)
	my_randombytes(challenge, len(challenge))
	my_randombytes(nonce, len(nonce))
	alicepk, alicesk = tweetnacl.crypto_box_keypair()
	bobpk, bobsk = tweetnacl.crypto_box_keypair()
	ret, crypted = my_crypto_box(challenge, nonce, alicepk, bobsk)
	assert(ret==0)
	ret, message = my_crypto_box_open(crypted, nonce, bobpk, alicesk)
	assert(ret==0)
	assert(arrtohex(challenge)==arrtohex(message))
	assert(hextoarr(arrtohex(bobsk)) == bobsk)
	"""

def main():
	if 0:
		pk, sk = gen_keypair()
		print arrtohex(pk)
		print arrtohex(sk)
		sys.exit(1)
	self_test()

	global server_pk, server_sk, client_pk, client_sk

#	server_pk, server_sk = tweetnacl.crypto_box_keypair()
#	client_pk, client_sk = tweetnacl.crypto_box_keypair()

	server_pk = hextoarr('8e3c5e9e22b7812e30ff2fa92cb964f71ac34aabe7c41c8a0ea85f7443e71d48')
	server_sk = hextoarr('18490c80f53f93d6e158b31e73ccbf53ad683da2ecadd00d1b4b3a8e09febd77')

	client_pk = hextoarr('3c20cf530a1e5d6cf2278c828010649a3cd7f77408004610cb686bf7b4320e37')
	client_sk = hextoarr('cb23ed86e5788dfcc3e672f54b038e0d36ad9e0a5368e136370482836c52a041')

	server_pk, server_sk = gen_keypair()

	chall = handshake_challenge(server_pk)
	print "chall:"
	print chall
	ret, resp = handshake_response(chall, client_pk, client_sk)
	print "resp:"
	print ret
	print resp
	if ret != 0: print "hs_response failed"
	ret = handshake_response_verify(chall, resp, client_pk, server_sk)
	if not ret: print "authentication failed"
	else: print "OK"

if __name__ == '__main__':
	main()

