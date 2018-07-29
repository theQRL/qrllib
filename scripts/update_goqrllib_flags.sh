#!/bin/bash
mv $1/goqrllib/goqrllib/goqrllib.go $1/goqrllib/goqrllib/temp.go
sed '/#define intgo swig_intgo/i #cgo LDFLAGS: '$1'/goqrllib/goqrllib/goqrllib.so\n#cgo CXXFLAGS: -I'$1'/src -I'$1'/deps\n' $1/goqrllib/goqrllib/temp.go > $1/goqrllib/goqrllib/goqrllib.go
rm $1/goqrllib/goqrllib/temp.go
