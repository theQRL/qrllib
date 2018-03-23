#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import subprocess

from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
from distutils.sysconfig import get_python_inc
import distutils.sysconfig as sysconfig


class CMakeBuild(build_ext):
    def run(self):
        if not os.path.exists(self.build_temp):
            os.makedirs(self.build_temp)

        env = os.environ.copy()
        env['CXXFLAGS'] = env.get('CXXFLAGS', '')
        env['CXXFLAGS'] += ' -DVERSION_INFO=\\"' + self.distribution.get_version() + '\\"'

        for ext in self.extensions:
            extension_path = os.path.abspath(os.path.dirname(self.get_ext_fullpath(ext.name)))

            cmake_call = ['cmake', ext.sourcedir,
                          '-DBUILD_PYTHON=ON',
                          '-DBUILD_TESTS=OFF',
                          '-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=' + extension_path,
                          '-DCMAKE_BUILD_TYPE=Release']

            # Detect conda
            if sys.platform == 'darwin' and 'CONDA_DEFAULT_ENV' in os.environ:
                print('OSX + Conda environment detected')
                python_include_dir = get_python_inc()
                python_library = os.path.join(sysconfig.get_config_var('LIBDIR'), sysconfig.get_config_var('LDLIBRARY'))
                cmake_call.extend(['-DPYTHON_INCLUDE_DIR=' + python_include_dir,
                                   '-DPYTHON_LIBRARY=' + python_library])

            subprocess.check_call(cmake_call, cwd=self.build_temp, env=env)

            subprocess.check_call(['cmake', '--build', '.',
                                   '--config', 'Release', '--', '-j2'], cwd=self.build_temp)


class CMakeExtension(Extension):
    def __init__(self, name, sourcedir='', *args, **kw):
        Extension.__init__(self, name, sources=[], *args, **kw)
        self.sourcedir = os.path.abspath(sourcedir)


def setup_package():
    needs_sphinx = {'build_sphinx', 'upload_docs'}.intersection(sys.argv)
    sphinx = ['sphinx'] if needs_sphinx else []
    cmake = []

    # noinspection PyInterpreter
    setup(setup_requires=['six', 'pytest-runner', 'pyscaffold>3'] + sphinx + cmake,
          packages=['pyqrllib', ],
          tests_require=['pytest', 'pytest-cov'],
          ext_modules=[CMakeExtension('pyqrllib')],
          cmdclass=dict(build_ext=CMakeBuild),
          use_pyscaffold=True)


if __name__ == "__main__":
    setup_package()
