#Protobuf

cd $BUILD_DIR
wget https://github.com/google/protobuf/releases/download/v$PROTOBUF_VER/protobuf-python-$PROTOBUF_VER.tar.gz
export PROTOBUF_DIR=$BUILD_DIR/protobuf-$PROTOBUF_VER
tar zxvf protobuf-python-$PROTOBUF_VER.tar.gz
# Make protoc first
cd $PROTOBUF_DIR
./configure && make -j2

# make the sdist of the python bindings module
cd $PROTOBUF_DIR/python
python3 setup.py --command-packages=stdeb.command sdist_dsc

# stdeb's sdist_dsc makes dist/, deb_dist, and protobuf-$PROTOBUF_VER.tar.gz.
# the source is copied under deb_dist/, but we need it to still think it's in $PROTOBUF_DIR/python for it to compile
cd $PROTOBUF_DIR/python/deb_dist
ln -s $PROTOBUF_DIR/src src

cd $PROTOBUF_DIR/python/deb_dist/protobuf-$PROTOBUF_VER
dpkg-buildpackage -rfakeroot -uc -us

# grpcio

cd $BUILD_DIR
export GRPCIO_DIR=grpcio-$GRPCIO_VER
export GRPCIO_TOOLS_DIR=grpcio-tools-$GRPCIO_VER
pip3 download --no-deps --no-binary :all: grpcio==$GRPCIO_VER grpcio-tools==$GRPCIO_VER
py2dsc --with-python2=False --with-python3=True grpcio-$GRPCIO_VER.tar.gz
cd deb_dist/$GRPCIO_DIR
dpkg-buildpackage

cd $BUILD_DIR
py2dsc --with-python2=False --with-python3=True grpcio-tools-$GRPCIO_VER.tar.gz
cd deb_dist/$GRPCIO_TOOLS_DIR
dpkg-buildpackage

# Move the Protobuf stuff to /build/deb_dist
mv $BUILD_DIR/$PROTOBUF_DIR/python/deb_dist/* $BUILD_DIR/deb_dist