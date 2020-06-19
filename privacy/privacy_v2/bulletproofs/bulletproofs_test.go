package bulletproofs

import (
	"fmt"
	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/privacy/operation"
	"github.com/incognitochain/incognito-chain/privacy/privacy_util"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"math/rand"
	"testing"
	"time"
)

var _ = func() (_ struct{}) {
	fmt.Println("This runs before init()!")
	Logger.Init(common.NewBackend(nil).Logger("test", true))
	return
}()

func TestMain(m *testing.M) {
	log.SetOutput(ioutil.Discard)
	m.Run()
}

func TestPad(t *testing.T) {
	data := []struct {
		number       int
		paddedNumber int
	}{
		{1000, 1024},
		{3, 4},
		{5, 8},
	}

	for _, item := range data {
		num := roundUpPowTwo(item.number)
		assert.Equal(t, item.paddedNumber, num)
	}
}

func TestPowerVector(t *testing.T) {
	twoVector := powerVector(new(operation.Scalar).FromUint64(2), 5)
	assert.Equal(t, 5, len(twoVector))
}

func TestInnerProduct(t *testing.T) {
	for j := 0; j < 5; j++ {
		n := privacy_util.MaxExp
		a := make([]*operation.Scalar, n)
		b := make([]*operation.Scalar, n)
		uinta := make([]uint64, n)
		uintb := make([]uint64, n)
		uintc := uint64(0)
		for i := 0; i < n; i++ {
			uinta[i] = uint64(rand.Intn(100000000))
			uintb[i] = uint64(rand.Intn(100000000))
			a[i] = new(operation.Scalar).FromUint64(uinta[i])
			b[i] = new(operation.Scalar).FromUint64(uintb[i])
			uintc += uinta[i] * uintb[i]
		}

		c, _ := innerProduct(a, b)
		assert.Equal(t, new(operation.Scalar).FromUint64(uintc), c)
	}
}

func TestEncodeVectors(t *testing.T) {
	for i := 0; i < 5; i++ {
		var AggParam = newBulletproofParams(1)
		n := privacy_util.MaxExp
		a := make([]*operation.Scalar, n)
		b := make([]*operation.Scalar, n)
		G := make([]*operation.PointExtended, n)
		H := make([]*operation.PointExtended, n)

		for j := range a {
			a[j] = operation.RandomScalar()
			b[j] = operation.RandomScalar()
			G[j] = new(operation.PointExtended).Set(AggParam.g[j])
			H[j] = new(operation.PointExtended).Set(AggParam.h[j])
		}

		actualRes, err := encodeVectors(a, b, G, H)
		if err != nil {
			fmt.Printf("Err: %v\n", err)
		}

		expectedRes := new(operation.PointExtended).Identity()
		for j := 0; j < n; j++ {
			expectedRes.Add(expectedRes, new(operation.PointExtended).ScalarMult(G[j], a[j]))
			expectedRes.Add(expectedRes, new(operation.PointExtended).ScalarMult(H[j], b[j]))
		}

		assert.Equal(t, expectedRes.ToBytes(), actualRes.ToBytes())
	}
}

func TestInnerProductProveVerify(t *testing.T) {
	for k := 0; k < 10; k++ {
		numValue := rand.Intn(privacy_util.MaxOutputCoin)
		numValuePad := roundUpPowTwo(numValue)
		aggParam := new(bulletproofParams)
		aggParam.g = AggParam.g[0 : numValuePad*privacy_util.MaxExp]
		aggParam.h = AggParam.h[0 : numValuePad*privacy_util.MaxExp]
		aggParam.u = AggParam.u
		aggParam.cs = AggParam.cs

		wit := new(InnerProductWitness)
		n := privacy_util.MaxExp * numValuePad
		wit.a = make([]*operation.Scalar, n)
		wit.b = make([]*operation.Scalar, n)

		for i := range wit.a {
			//wit.a[i] = privacy.RandomScalar()
			//wit.b[i] = privacy.RandomScalar()
			wit.a[i] = new(operation.Scalar).FromUint64(uint64(rand.Intn(100000)))
			wit.b[i] = new(operation.Scalar).FromUint64(uint64(rand.Intn(100000)))
		}

		c, _ := innerProduct(wit.a, wit.b)
		wit.p = new(operation.PointExtended).ScalarMult(aggParam.u, c)

		for i := range wit.a {
			wit.p.Add(wit.p, new(operation.PointExtended).ScalarMult(aggParam.g[i], wit.a[i]))
			wit.p.Add(wit.p, new(operation.PointExtended).ScalarMult(aggParam.h[i], wit.b[i]))
		}

		proof, err := wit.Prove(aggParam.g, aggParam.h, aggParam.u, aggParam.cs.ToBytesS())
		if err != nil {
			fmt.Printf("Err: %v\n", err)
			return
		}
		res2 := proof.Verify(aggParam.g, aggParam.h, aggParam.u, aggParam.cs.ToBytesS())
		assert.Equal(t, true, res2)
		res2prime := proof.VerifyFaster(aggParam.g, aggParam.h, aggParam.u, aggParam.cs.ToBytesS())
		assert.Equal(t, true, res2prime)

		bytes := proof.Bytes()
		proof2 := new(InnerProductProof)
		proof2.SetBytes(bytes)
		res3 := proof2.Verify(aggParam.g, aggParam.h, aggParam.u, aggParam.cs.ToBytesS())
		assert.Equal(t, true, res3)
		res3prime := proof2.Verify(aggParam.g, aggParam.h, aggParam.u, aggParam.cs.ToBytesS())
		assert.Equal(t, true, res3prime)
	}
}

func TestAggregatedRangeProveVerify(t *testing.T) {
	for i := 0; i < 4; i++ {
		//prepare witness for Aggregated range protocol
		wit := new(AggregatedRangeWitness)
		numValue := rand.Intn(privacy_util.MaxOutputCoin)
		values := make([]uint64, numValue)
		rands := make([]*operation.Scalar, numValue)

		for i := range values {
			values[i] = uint64(rand.Uint64())
			rands[i] = operation.RandomScalar()
		}
		wit.Set(values, rands)

		// proving
		proof, err := wit.Prove()
		assert.Equal(t, nil, err)

		// validate sanity for proof
		isValidSanity := proof.ValidateSanity()
		assert.Equal(t, true, isValidSanity)

		// convert proof to bytes array
		bytes := proof.Bytes()
		expectProofSize := EstimateMultiRangeProofSize(numValue)
		assert.Equal(t, int(expectProofSize), len(bytes))

		// new aggregatedRangeProof from bytes array
		proof2 := new(AggregatedRangeProof)
		proof2.SetBytes(bytes)

		// verify the proof
		res, err := proof2.Verify()
		assert.Equal(t, true, res)
		assert.Equal(t, nil, err)

		// verify the proof faster
		res, err = proof2.VerifyFaster()

		assert.Equal(t, true, res)
		assert.Equal(t, nil, err)
	}
}

func TestAggregatedRangeProveVerifyBatch(t *testing.T) {
	count := 10
	proofs := make([]*AggregatedRangeProof, 0)

	for i := 0; i < count; i++ {
		//prepare witness for Aggregated range protocol
		wit := new(AggregatedRangeWitness)
		numValue := rand.Intn(privacy_util.MaxOutputCoin)
		values := make([]uint64, numValue)
		rands := make([]*operation.Scalar, numValue)

		for i := range values {
			values[i] = uint64(rand.Uint64())
			rands[i] = operation.RandomScalar()
		}
		wit.Set(values, rands)

		// proving
		proof, err := wit.Prove()
		assert.Equal(t, nil, err)

		res, err := proof.Verify()
		assert.Equal(t, true, res)
		assert.Equal(t, nil, err)

		res, err = proof.VerifyFaster()
		assert.Equal(t, true, res)
		assert.Equal(t, nil, err)

		proofs = append(proofs, proof)
	}
	// verify the proof faster
	res, err, _ := VerifyBatch(proofs)
	assert.Equal(t, true, res)
	assert.Equal(t, nil, err)
}

func TestBenchmarkAggregatedRangeProveVerifyUltraFast(t *testing.T) {
	for k := 1; k < 20; k += 1 {
		count := k
		proofs := make([]*AggregatedRangeProof, 0)
		start := time.Now()
		t1 := time.Now().Sub(start)
		for i := 0; i < count; i++ {
			//prepare witness for Aggregated range protocol
			wit := new(AggregatedRangeWitness)
			//numValue := rand.Intn(MaxOutputNumber)
			numValue := 8
			values := make([]uint64, numValue)
			rands := make([]*operation.Scalar, numValue)

			for i := range values {
				values[i] = uint64(rand.Uint64())
				rands[i] = operation.RandomScalar()
			}
			wit.Set(values, rands)

			// proving
			proof, err := wit.Prove()
			assert.Equal(t, nil, err)
			start := time.Now()
			proof.VerifyFaster()
			t1 += time.Now().Sub(start)

			proofs = append(proofs, proof)
		}
		// verify the proof faster
		start = time.Now()
		res, err, _ := VerifyBatch(proofs)
		fmt.Println(k+1, t1.Seconds(), time.Now().Sub(start).Seconds())

		assert.Equal(t, true, res)
		assert.Equal(t, nil, err)
	}
}

func benchmarkAggRangeProof_Proof(numberofOutput int, b *testing.B) {
	wit := new(AggregatedRangeWitness)
	values := make([]uint64, numberofOutput)
	rands := make([]*operation.Scalar, numberofOutput)

	for i := range values {
		values[i] = uint64(rand.Uint64())
		rands[i] = operation.RandomScalar()
	}
	wit.Set(values, rands)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		wit.Prove()
	}
}

func benchmarkAggRangeProof_Verify(numberofOutput int, b *testing.B) {
	wit := new(AggregatedRangeWitness)
	values := make([]uint64, numberofOutput)
	rands := make([]*operation.Scalar, numberofOutput)

	for i := range values {
		values[i] = uint64(common.RandInt64())
		rands[i] = operation.RandomScalar()
	}
	wit.Set(values, rands)
	proof, _ := wit.Prove()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		proof.Verify()
	}
}

func benchmarkAggRangeProof_VerifyFaster(numberofOutput int, b *testing.B) {
	wit := new(AggregatedRangeWitness)
	values := make([]uint64, numberofOutput)
	rands := make([]*operation.Scalar, numberofOutput)

	for i := range values {
		values[i] = uint64(common.RandInt64())
		rands[i] = operation.RandomScalar()
	}
	wit.Set(values, rands)
	proof, _ := wit.Prove()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		proof.VerifyFaster()
	}
}

func TestPower(t *testing.T){
	y := operation.RandomScalar()


	one := new(operation.Scalar).FromUint64(1)


	start := time.Now()
	oneVector := powerVector(one, 64)
	yVector := powerVector(y, 64)
	actual, _ := innerProduct(oneVector, yVector)
	fmt.Println(time.Now().Sub(start).Seconds())

	start = time.Now()
	yPow := new(operation.Scalar).Exp(y, 64)
	expect := new(operation.Scalar).Sub(yPow, one)
	expect = expect.Mul(expect, new(operation.Scalar).Invert(new(operation.Scalar).Sub(y, one)))
	fmt.Println(time.Now().Sub(start).Seconds())

	assert.Equal(t, expect.ToBytes(), actual.ToBytes())
}


func BenchmarkVerifyBatch(b *testing.B) {
	numBatch := 64
	numValue := 8
	proofs := make([]*AggregatedRangeProof, 0)
	for k := 1; k < numBatch; k += 1 {
		//prepare witness for Aggregated range protocol
		wit := new(AggregatedRangeWitness)
		//numValue := rand.Intn(MaxOutputNumber)
		values := make([]uint64, numValue)
		rands := make([]*operation.Scalar, numValue)

		for i := range values {
			values[i] = uint64(rand.Uint64())
			rands[i] = operation.RandomScalar()
		}
		wit.Set(values, rands)

		// proving
		proof, _ := wit.Prove()
		res, _ := proof.VerifyFaster()

		if !res {
			fmt.Println("Not True")
			return
		}

		proofs = append(proofs, proof)
	}
	b.ResetTimer()
	res, err, _ := VerifyBatch(proofs)

	if !res {
		fmt.Println("Ahihi")
		panic(err)
	}
}

func BenchmarkAggregatedRangeWitness_Prove1(b *testing.B) { benchmarkAggRangeProof_Proof(1, b) }
func BenchmarkAggregatedRangeProof_Verify1(b *testing.B)  { benchmarkAggRangeProof_Verify(1, b) }
func BenchmarkAggregatedRangeProof_VerifyFaster1(b *testing.B) {
	benchmarkAggRangeProof_VerifyFaster(1, b)
}

func BenchmarkAggregatedRangeWitness_Prove2(b *testing.B) { benchmarkAggRangeProof_Proof(2, b) }
func BenchmarkAggregatedRangeProof_Verify2(b *testing.B)  { benchmarkAggRangeProof_Verify(2, b) }
func BenchmarkAggregatedRangeProof_VerifyFaster2(b *testing.B) {
	benchmarkAggRangeProof_VerifyFaster(2, b)
}

func BenchmarkAggregatedRangeWitness_Prove4(b *testing.B) { benchmarkAggRangeProof_Proof(4, b) }
func BenchmarkAggregatedRangeProof_Verify4(b *testing.B)  { benchmarkAggRangeProof_Verify(4, b) }
func BenchmarkAggregatedRangeProof_VerifyFaster4(b *testing.B) {
	benchmarkAggRangeProof_VerifyFaster(4, b)
}

func BenchmarkAggregatedRangeWitness_Prove8(b *testing.B) { benchmarkAggRangeProof_Proof(8, b) }
func BenchmarkAggregatedRangeProof_Verify8(b *testing.B)  { benchmarkAggRangeProof_Verify(8, b) }
func BenchmarkAggregatedRangeProof_VerifyFaster8(b *testing.B) {
	benchmarkAggRangeProof_VerifyFaster(8, b)
}

func BenchmarkAggregatedRangeWitness_Prove16(b *testing.B) { benchmarkAggRangeProof_Proof(16, b) }
func BenchmarkAggregatedRangeProof_Verify16(b *testing.B)  { benchmarkAggRangeProof_Verify(16, b) }
func BenchmarkAggregatedRangeProof_VerifyFaster16(b *testing.B) {
	benchmarkAggRangeProof_VerifyFaster(16, b)
}

func BenchmarkAggregatedRangeWitness_Prove32(b *testing.B) { benchmarkAggRangeProof_Proof(32, b) }
func BenchmarkAggregatedRangeProof_Verify32(b *testing.B)  { benchmarkAggRangeProof_Verify(32, b) }
func BenchmarkAggregatedRangeProof_VerifyFaster32(b *testing.B) {
	benchmarkAggRangeProof_VerifyFaster(32, b)
}
