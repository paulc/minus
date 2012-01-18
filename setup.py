#!/usr/bin/env python

from distutils.core import Command,setup

import minus
long_description = "\n".join([l[4:] for l in minus.__doc__.split("\n")]) + "\n"
version = minus.VERSION

class GenerateReadme(Command):
    description = "Generates README file from long_description"
    user_options = []
    def initialize_options(self): pass
    def finalize_options(self): pass
    def run(self):
        open("README","w").write(long_description)

setup(name='minus',
      version = version,
      description = 'Python library & command-line utility which interacts with the minus.com (http://minus.com) file sharing service',
      long_description = long_description,
      author = 'Paul Chakravarti',
      author_email = 'paul.chakravarti@gmail.com',
      url = 'http://bitbucket.org/paulc/minus/',
      cmdclass = { 'readme' : GenerateReadme },
      py_modules = ['minus'],
      scripts= ['minus.py'],
      license = 'BSD',
      classifiers = [ "Topic :: Communications :: File Sharing",
                      "Topic :: Software Development :: Libraries",
                    ]
     )
