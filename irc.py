# -*- coding: utf-8 -*-

from rocksock import Rocksock, RocksockException

class RsIRC():
	def __init__(self, host, port, nickname, username="foo", realname=None, ssl=False, timeout=60, **kwargs):
		self.host = host
		self.port = port
		self.use_ssl = ssl
		self.debugreq = False
		self.nickname = nickname
		self.username = username
		self.realname = realname
		if not self.username or not self.nickname:
			raise("username and nickname may not be None")
		if not self.realname: self.realname = self.username
		self.timeout = timeout
		self.conn = None
		self.reconnect()

	def sendl(self, s):
		return self._send("%s\r\n"%s)

	def privmsg(self, chan, msg):
		self.sendl("PRIVMSG %s :%s" %( chan, msg ))

	def _handshake(self):
		self.sendl("NICK %s" % (self.nickname))
		self.sendl("USER %s %s %s :%s"% (self.username, self.realname, self.host, self.nickname))

	def reconnect(self):
		while True:
			try:
				if self.conn: self.conn.disconnect()
				self.conn = Rocksock(host=self.host, port=self.port, ssl=self.use_ssl, timeout=self.timeout)
				self.conn.connect()
				self._handshake()
				break
			except RocksockException as e:
				print e.get_errormessage()
				import time
				time.sleep(0.05)
				continue

	def _send(self, req):
		if self.conn is None: self.reconnect()
		while True:
			try:
				self.conn.send(req)
				return

			except RocksockException as e:
				self.conn.disconnect()
				self.reconnect()
			"""
			except IOError:
				self.conn.disconnect()
				self.reconnect()
			except EOFError:
				self.conn.disconnect()
				self.reconnect()
			except ssl.SSLError:
				self.conn.disconnect()
				self.reconnect()
			"""

	def readline(self):
		if self.conn is None: self.reconnect()
		while True:
			try:
				return self.conn.recvline().rstrip('\r\n')
			except RocksockException as e:
				print "XXX" + e.get_errormessage()
				e.reraise()
				self.reconnect()

