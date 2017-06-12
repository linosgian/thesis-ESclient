# Decorator that registers processors to Detectors
def register_proc(*classes):
	def decorated(f):
		for cls in classes:
			if hasattr(cls, 'processors'):
				cls.processors.append(f)
			else: setattr(cls, 'processors', [f])
		return f	
	return decorated

class colors:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

import inspect

def whoami():
   return inspect.stack()[1][3]

class UserLog:
   def info(self, format_string):
      print("{0}[*]{1}{2}".format(colors.GREEN,format_string,colors.END))
   def warn(self, format_string, bold=True):
      if bold:
         print("{0}{1}[*]{2}{3}".format(colors.YELLOW,colors.BOLD,format_string,colors.END))
      else:
         print("{0}[*]{1}{2}".format(colors.YELLOW,format_string,colors.END))
   def error(self, format_string):
      print("{0}[*]{1}{2}".format(colors.RED,format_string,colors.END))
