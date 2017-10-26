#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import subprocess
import platform

from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext


class CMakeBuild(build_ext):
    def run(self):
        if not os.path.exists(self.build_temp):
            os.makedirs(self.build_temp)

        env = os.environ.copy()
        env['CXXFLAGS'] = env.get('CXXFLAGS', '')
        env['CXXFLAGS'] += ' -DVERSION_INFO=\\"'+self.distribution.get_version()+'\\"'

        for ext in self.extensions:
            extension_path = os.path.abspath(os.path.dirname(self.get_ext_fullpath(ext.name)))

            subprocess.check_call(['cmake', ext.sourcedir,
                                   '-DBUILD_PYTHON=ON',
                                   '-DBUILD_TESTS=OFF',
                                   '-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=' + extension_path,
                                   '-DCMAKE_BUILD_TYPE=Release'], cwd=self.build_temp, env=env)

            subprocess.check_call(['cmake', '--build', '.',
                                   '--config', 'Release', '--', '-j4'], cwd=self.build_temp)


class CMakeExtension(Extension):
    def __init__(self, name, sourcedir='', *args, **kw):
        Extension.__init__(self, name, sources=[], *args, **kw)
        self.sourcedir = os.path.abspath(sourcedir)


def setup_package():
    needs_sphinx = {'build_sphinx', 'upload_docs'}.intersection(sys.argv)
    sphinx = ['sphinx'] if needs_sphinx else []

    cmake = []
    # cmake = ['cmake']
    # if 'arm' in platform.machine():
    #     print("ARM platform detected. Skipping cmake")
    #     cmake = []

    setup(setup_requires=['six', 'pyscaffold>=2.5a0,<2.6a0'] + sphinx + cmake,
          packages=['pyqrllib', ],
          ext_modules=[CMakeExtension('pyqrllib')],
          cmdclass=dict(build_ext=CMakeBuild),
          use_pyscaffold=True)


if __name__ == "__main__":
    setup_package()
