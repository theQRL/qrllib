package misc

import (
	"bytes"
	"github.com/theQRL/qrllib/goqrllib/goqrllib"
)

type UcharVector struct {
	data goqrllib.UcharVector
}

func (v *UcharVector) AddBytes(data []byte) {
	for _, element := range data {
		v.data.Add(element)
	}
}

func (v *UcharVector) AddByte(data byte) {
	v.data.Add(data)
}

func (v *UcharVector) GetBytesBuffer() bytes.Buffer {
	var data bytes.Buffer
	for i := int64(0); i < v.data.Size(); i++ {
		value := v.data.Get(int(i))
		data.WriteByte(value)
	}
	return data
}

func (v *UcharVector) GetBytes() []byte {
	data := v.GetBytesBuffer()
	return data.Bytes()
}

func (v *UcharVector) GetString() string {
	data := v.GetBytesBuffer()
	return data.String()
}

func (v *UcharVector) GetData() goqrllib.UcharVector {
	return v.data
}

func (v *UcharVector) AddAt() goqrllib.UcharVector {
	return v.data
}

func (v *UcharVector) New(data goqrllib.UcharVector) {
	v.data = data
}

func BytesToUCharVector(data []byte) goqrllib.UcharVector {
	vector := goqrllib.NewUcharVector__SWIG_0()
	for _, element := range data {
		vector.Add(element)
	}

	return vector
}

func Int64ToUCharVector(data int64) goqrllib.UcharVector {
	return goqrllib.NewUcharVector__SWIG_1(data)
}

func UCharVectorToBytes(data goqrllib.UcharVector) []byte  {
	vector := UcharVector{}
	vector.New(data)

	return vector.GetBytes()
}

func UCharVectorToString(data goqrllib.UcharVector) string  {
	return string(UCharVectorToBytes(data))
}

func Reverse(s [][]byte) [][]byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}

	return s
}