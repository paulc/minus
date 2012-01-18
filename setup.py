#!/usr/bin/env python

from distutils.core import Command,setup

import sys
sys.path.append("src")
import minus
long_description = minus.__doc__.rstrip() + "\n"
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
      packages = ['minus'],
      package_dir = {'minus':'src'},
      license = 'BSD',
      classifiers = [ "Topic :: Communications :: File Sharing",
                      "Topic :: Software Development :: Libraries" ]
     )
