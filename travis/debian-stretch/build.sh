cd /build
pip3 download pyqrllib --no-deps
py2dsc-deb --with-python2=False --with-python3=True pyqrllib-*.tar.gz
