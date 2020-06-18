package operation

import (
	"fmt"
	C25519 "github.com/incognitochain/incognito-chain/privacy/operation/curve25519"
	"github.com/stretchr/testify/assert"
	"testing"
)

func BenchmarkPointExtended_AddPedersen(b *testing.B) {
	a := RandomScalar()
	c := RandomScalar()

	A := RandomPointExtended()
	C := RandomPointExtended()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		new(PointExtended).AddPedersen(a, A, c, C)
	}
}

func TestPointExtended_FromBytes(t *testing.T) {
	for i:=0; i<1000;i++ {
		p := RandomPointExtended()
		expected := p.ToBytes()

		tmp := new(C25519.Key)
		tmp.FromBytes(expected)
		actual, err := new(PointExtended).FromBytes(tmp)

		if err != nil {
			panic("Invalid input!")
		}

		assert.Equal(t, actual.ToBytes(), expected)
	}
}

func TestPointExtended_ToPoint(t *testing.T) {
	for i:=0; i< 1000; i++ {
		a := C25519.RandomPubKey()
		pointExtended , err:= new(PointExtended).FromBytes(a)

		if err != nil {
			panic("Invalid input")
		}

		actual := pointExtended.ToPoint()

		expected := &Point{*a}

		assert.Equal(t, actual, expected)
	}
}

func TestPointExtended_FromPoint(t *testing.T) {
	for i:=0; i< 1000; i++ {
		p := RandomPoint()

		actual := new(PointExtended).FromPoint(p)
		expected , err := new(PointExtended).FromBytes(&p.key)

		if err != nil {
			panic("Invalid input!")
		}

		assert.Equal(t, actual, expected)
	}

}

func TestPointExtended_ToBytes(t *testing.T) {
	for i:=0; i<1000; i++ {
		a := C25519.RandomPubKey()

		point, err := new(PointExtended).FromBytes(a)
		if err != nil {
			panic("Invalid input!")
		}

		expected := point.ToBytes()

		assert.Equal(t, a.ToBytes(), expected)
	}
}

func TestPointExtended_Add(t *testing.T) {
	for i:=0; i< 1000; i++ {
		a := C25519.RandomPubKey()
		b := C25519.RandomPubKey()

		pA := &Point{*a}
		pB := &Point{*b}

		peA, err := new(PointExtended).FromBytes(a)
		if err != nil {
			panic("Invalid input!")
		}
		peB, err := new(PointExtended).FromBytes(b)
		if err != nil {
			panic("Invalid input!")
		}

		expected := new(Point).Add(pA, pB)
		actual := new(PointExtended).Add(peA, peB)

		assert.Equal(t, actual.ToBytes(), expected.ToBytes())

	}
}

func TestPointExtended_Sub(t *testing.T) {
	for i:=0; i< 1000; i++ {
		a := C25519.RandomPubKey()
		b := C25519.RandomPubKey()

		pA := &Point{*a}
		pB := &Point{*b}

		peA, err := new(PointExtended).FromBytes(a)
		if err != nil {
			panic("Invalid input!")
		}
		peB, err := new(PointExtended).FromBytes(b)
		if err != nil {
			panic("Invalid input!")
		}

		expected := new(Point).Sub(pA, pB)
		actual := new(PointExtended).Sub(peA, peB)

		assert.Equal(t, actual.ToBytes(), expected.ToBytes())

	}
}

func TestPointExtended_Identity(t *testing.T) {
	p := new(Point).Identity()
	q := new(PointExtended).FromPoint(p)

	assert.Equal(t, q.IsIdentity(), true)
}

func TestIsPointExtendedEqual(t *testing.T) {
	for i :=0; i< 1000;i++{
		a := RandomPoint()
		peA := new(PointExtended).FromPoint(a)

		h := RandomScalar()
		pA := new(Point).ScalarMult(a, h)

		expected := new(PointExtended).FromPoint(pA)
		actual := new(PointExtended).ScalarMult(peA, h)

		assert.Equal(t, IsPointExtendedEqual(actual, expected), true)
	}
}

func TestPointExtended_ScalarMultBase(t *testing.T) {
	G := new(PointExtended).ScalarMultBase(new(Scalar).FromUint64(1))
	Gbytes := G.ToBytes()
	fmt.Printf("Gbytes: %v\n", Gbytes)

	array := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	aScalar := new(Scalar)
	aScalar.FromBytesS(array)
	res1 := new(PointExtended).ScalarMultBase(aScalar)
	res2 := new(PointExtended).ScalarMult(G, aScalar)
	//fmt.Printf("Res1: %v\n", res1.ToBytesS())
	//fmt.Printf("Res2: %v\n", res2.ToBytesS())

	assert.Equal(t, res1.ToBytes(), res2.ToBytes(), "ScalarMultBase should be correct")

	for i := 0; i < 1000; i++ {
		a := RandomScalar()
		b := RandomScalar()

		res1 := new(PointExtended).ScalarMultBase(a)
		res2 := new(PointExtended).ScalarMultBase(b)
		res := new(PointExtended).Add(res1, res2)

		resPrime1 := C25519.ScalarmultBase(&a.key)
		resPrime2 := C25519.ScalarmultBase(&b.key)
		var resPrime C25519.Key

		C25519.AddKeys(&resPrime, resPrime1, resPrime2)

		assert.Equal(t, resPrime.ToBytes(), res.ToBytes())
	}
}

func TestPointExtended_MultiScalarMult(t *testing.T) {
	for j :=0; j< 100; j++ {
		k := 1000
		var scalarLs  []*Scalar
		var pointLs []*PointExtended
		expected := new(PointExtended).Identity()
		for i:=0;i<k ; i++{
			scalarLs = append(scalarLs, RandomScalar())
			pointLs = append(pointLs, new(PointExtended).ScalarMultBase(RandomScalar()))
			expected = expected.Add(expected, new(PointExtended).ScalarMult(pointLs[i], scalarLs[i]))
		}

		actual := new(PointExtended).MultiScalarMult(scalarLs, pointLs)

		assert.Equal(t, IsPointExtendedEqual(actual, expected), true)
	}
}