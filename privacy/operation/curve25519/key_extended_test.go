package curve25519

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestAddKeysExtended(t *testing.T) {
	start := time.Now()
	t1 := time.Now().Sub(start)
	t2 := t1
	testNum := 1000
	for i:=0; i< testNum; i++ {
		a := RandomScalar()
		b := RandomScalar()

		c := new(Key)
		start = time.Now()
		AddKeys(c, a, b)
		t1 += time.Now().Sub(start)

		A := new(KeyExtended)
		B := new(KeyExtended)
		C := new(KeyExtended)

		A.FromBytes(a)
		B.FromBytes(b)


		start = time.Now()

		AddKeysExtended(C, A, B)
		c2 := Key(C.ToBytes())

		t2 += time.Now().Sub(start)




		assert.Equal(t, c, &c2)
	}

	fmt.Println("Number of Tests", testNum)
	fmt.Println("Compressed", t1.Seconds())
	fmt.Println("Decompressed", t2.Seconds())
	fmt.Println("Ratio", t1.Seconds()/t2.Seconds())
}

func TestScalarMultBaseExtended(t *testing.T) {
	start := time.Now()
	t1 := time.Now().Sub(start)
	t2 := t1
	testNum := 1000
	for i:=0; i< testNum; i++ {
		a := RandomScalar()
		start = time.Now()
		aG := ScalarmultBase(a)
		t1 += time.Now().Sub(start)


		start = time.Now()
		AG := ScalarMultBaseExtended(a)
		t2 += time.Now().Sub(start)

		a2 := Key(AG.ToBytes())
		assert.Equal(t, aG, &a2)
	}

	fmt.Println("Number of Tests", testNum)
	fmt.Println("Compressed", t1.Seconds())
	fmt.Println("Decompressed", t2.Seconds())
	fmt.Println("Ratio", t1.Seconds()/t2.Seconds())
}

func TestScalarMultKeyExtended(t *testing.T) {
	start := time.Now()
	t1 := time.Now().Sub(start)
	t2 := t1
	testNum := 1000
	for i:=0; i< testNum; i++ {
		a := RandomScalar()
		p := RandomScalar()

		start = time.Now()
		aP := ScalarMultKey(p, a)
		t1 += time.Now().Sub(start)

		P := new(KeyExtended)
		P.FromBytes(p)

		start = time.Now()
		res := ScalarMultKeyExtended(P, a)
		t2 += time.Now().Sub(start)

		a2 := Key(res.ToBytes())

		assert.Equal(t, aP, &a2)
	}

	fmt.Println("Number of Tests", testNum)
	fmt.Println("Compressed", t1.Seconds())
	fmt.Println("Decompressed", t2.Seconds())
	fmt.Println("Ratio", t1.Seconds()/t2.Seconds())


}

func TestKeyExtended_FromBytes(t *testing.T) {
	for i:=0; i< 1000; i++ {
		expected := RandomKeyExtended()

		tmp := expected.ToBytes()

		actual := new(KeyExtended)
		key := new(Key)
		key.FromBytes(tmp)

		err := actual.FromBytes(key)

		if err != nil {
			fmt.Println(tmp)
			fmt.Println(key)
			fmt.Println(key.Private_Key_Valid())
			panic("Invalid input!")
		}

		assert.Equal(t, actual, expected)
	}
}

func TestKeyExtended_ToBytes(t *testing.T) {
	for i:= 0; i< 1000; i++ {
		expected := RandomPubKey()

		tmp := new(KeyExtended)
		err := tmp.FromBytes(expected)

		if err != nil {
			panic("Invalid input!")
		}

		actual := tmp.ToBytes()

		assert.Equal(t, actual, expected.ToBytes())

	}
}

func TestKeyExtended_HashToEC(t *testing.T) {
	for i:=0; i< 1000; i++ {
		p := RandomPubKey()

		expected := p.HashToEC()

		q := new(KeyExtended)

		err := q.FromBytes(p)
		if err != nil {
			panic("Invalid input!")
		}

		actual := q.HashToEC()

		assert.Equal(t, expected, actual.Point)
	}
}