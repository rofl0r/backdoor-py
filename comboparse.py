from ConfigParser import SafeConfigParser, NoOptionError
from argparse import ArgumentParser
import sys

class _Dummy():
	pass

class ComboParser(object):
	def __init__(self, ini):
		self.items = []
		self.cparser = SafeConfigParser()
		self.aparser = ArgumentParser()
		self.ini = ini
		self.items = []
		self.loaded = False
		self.args = None

	def add_item(self, section, name, type, default, desc, required):
		def str2bool(val):
			return val in ['True', 'true', '1', 'yes']
		self.items.append({
			'section':section,
			'name':name,
			'type':type,
			'default':default,
			'required':required,
		})
		argstr = '--%s.%s'%(section, name) if section != 'DEFAULT' else '--%s'%(name)
		self.aparser.add_argument(
			argstr,
			help='%s, default: (%s)'%(desc, str(default)),
			type=type if type is not bool else str2bool,
			default=None,
			required=False
		)
	def load(self):
		if self.loaded: return
		self.loaded = True

		try: self.cparser.read(self.ini)
		except: pass
		self.args = self.aparser.parse_args()
		for item in self.items:
			if item['section'] != 'DEFAULT':
				try:
					obj = getattr(self, item['section'])
				except AttributeError:
					setattr(self, item['section'], _Dummy())
					obj = getattr(self, item['section'])
			else:
				obj = self

			setattr(obj, item['name'], item['default'])
			inner = getattr(obj, item['name'])

			item['found'] = True
			try:
				if   item['type'] is bool : inner = self.cparser.getboolean(item['section'], item['name'])
				elif item['type'] is float: inner = self.cparser.getfloat(item['section'], item['name'])
				elif item['type'] is int  : inner = self.cparser.getint(item['section'], item['name'])
				elif item['type'] is str  : inner = self.cparser.get(item['section'], item['name'])
			except NoOptionError:
				item['found'] = False
			try:
				argstr = '%s.%s'%(item['section'], item['name']) if item['section'] != 'DEFAULT' else '%s'%(item['name'])
				arg = getattr(self.args, argstr)
				if arg is not None:
					inner = arg
					item['found'] = True
			except AttributeError: pass
			if not item['found']:
				if item['required']:
					sys.stderr.write('error: required config item "%s" not found in section "%s" of "%s"!\n'%(item['name'], item['section'], self.ini))
					sys.exit(1)
				else:
					#sys.stderr.write('warning: assigned default value of "%s" to "%s.%s"\n'%(str(item['default']), item['section'], item['name']))
					pass
			setattr(obj, item['name'], inner)


# TEST CODE
def _main():
	config = ComboParser('config.ini')
	config.add_item('watchd', 'debug', bool, False, 'turn additional debug info on', False)
	config.add_item('watchd', 'float', float, 0.1, 'a float test', True)
	config.add_item('watchd', 'strupp', str, "sup", 'a str test', False)
	config.add_item('common', 'tor_host', str, '127.0.0.1:9050', 'address of tor proxy', True)
	config.load()
	print config.watchd.debug
	print config.watchd.float
	print config.watchd.strupp
	print config.common.tor_host

if __name__ == '__main__':
	_main()
