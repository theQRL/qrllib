cd /build
export VERSION=$(git tag --points-at HEAD --list 'v*')  # should store something like v0.2.6
python3 setup.py --command-packages=stdeb.command sdist_dsc
py2dsc-deb --with-python2=False --with-python3=True pyqrllib-${VERSION:1}.tar.gz  # we only need 0.2.6, not v0.2.6