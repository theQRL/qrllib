#!/bin/bash
mv $1/goqrllib/dilithium/dilithium.go $1/goqrllib/dilithium/temp.go
sed '/#define intgo swig_intgo/i #cgo LDFLAGS: '$1'/goqrllib/dilithium/godilithium.so\n#cgo CXXFLAGS: -I'$1'/src -I'$1'/deps\n' $1/goqrllib/dilithium/temp.go > $1/goqrllib/dilithium/dilithium.go
rm $1/goqrllib/dilithium/temp.go
