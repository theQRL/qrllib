#!/bin/bash
mv $1/goqrllib/kyber/kyber.go $1/goqrllib/kyber/temp.go
sed '/#define intgo swig_intgo/i #cgo LDFLAGS: '$1'/goqrllib/kyber/gokyber.so\n#cgo CXXFLAGS: -I'$1'/src -I'$1'/deps\n' $1/goqrllib/kyber/temp.go > $1/goqrllib/kyber/kyber.go
rm $1/goqrllib/kyber/temp.go
