// Copyright 2017-2018 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package curve25519

import (
	"crypto/rand"
	"errors"
)

// KeyExtended is the full version of the key (decompressed)
type KeyExtended struct{
	Point *ExtendedGroupElement
}


func (p *ProjectiveGroupElement) ToExtended()  *ExtendedGroupElement {
	r := new(ExtendedGroupElement)
	if r == nil{
		r = new(ExtendedGroupElement)
	}
	FeCopy(&r.X, &p.X)
	FeCopy(&r.Y, &p.Y)
	FeCopy(&r.Z, &p.Z)
	FeMul(&r.T, &p.X, &p.Y)
	var inverseZ = new(FieldElement)
	FeInvert(inverseZ, &p.Z)
	FeMul(&r.T, &r.T, inverseZ)

	return r
}

func (p *KeyExtended) FromBytes(s *Key) error{
	if p.Point == nil{
		p.Point = new(ExtendedGroupElement)
	}
	if !p.Point.FromBytes(s){
		return errors.New("Point is invalid!")
	}
	return nil
}

func (p *KeyExtended) ToBytes() [KeyLength]byte{
	var s = new(Key)
	p.Point.ToBytes(s)
	return s.ToBytes()
}

func (p *KeyExtended) HashToEC() (result *KeyExtended) {
	var p1 ProjectiveGroupElement
	var p2 CompletedGroupElement
	toBeHashed := p.ToBytes()
	h := Key(Keccak256(toBeHashed[:]))
	p1.FromBytes(&h)

	// fmt.Printf("p1 %+v\n", p1)
	GeMul8(&p2, &p1)
	result = new(KeyExtended)
	result.Point = new(ExtendedGroupElement)
	p2.ToExtended(result.Point)

	return
}

func (p *KeyExtended) HashToPoint() (result *KeyExtended) {
	result = new(KeyExtended)
	result= p.HashToEC()
	return
}

// compatible with hashToPointSimple
// NOTE: this is incompatible with HashToPoint ( though it should have been)
// there are no side-effects or degradtion of curve25519, due to this
// however, the mistakes have to kept as they were in original code base
// this function is only used to generate H from G
func (p *KeyExtended) HashToPointSimple() (result KeyExtended) {
	toBeHashed := p.ToBytes()
	h := Key(Keccak256(toBeHashed[:]))
	extended := new(ExtendedGroupElement)
	extended.FromBytes(&h)

	// convert extended to projective
	var p1 ProjectiveGroupElement

	extended.ToProjective(&p1)
	var p2 CompletedGroupElement

	GeMul8(&p2, &p1)
	p2.ToExtended(extended)
	result = *new(KeyExtended)
	result.Point = new(ExtendedGroupElement)
	result.Point = extended
	return
}

func RandomPoint()  *KeyExtended {
	var result = new(Key)
	var reduceFrom [KeyLength * 2]byte
	tmp := make([]byte, KeyLength*2)
	rand.Read(tmp)
	copy(reduceFrom[:], tmp)
	ScReduce(result, &reduceFrom)

	var res = new(KeyExtended)
	res.Point = result.ToExtended()

	return res
}

// generate a new private-public key pair
func NewKeyPair2() (privKey *Key, pubKey *KeyExtended) {
	privKey = RandomScalar()
	pubKey = &KeyExtended{privKey.PublicKey().ToExtended()}
	return
}

func ScalarMultBaseExtended(a *Key) (aG *KeyExtended) {
	reduce32copy := a
	ScReduce32(reduce32copy)
	point := new(ExtendedGroupElement)
	GeScalarMultBase(point, a)
	aG = new(KeyExtended)
	aG.Point = point
	return
}

// does a * P where a is a scalar and P is an arbitrary point
func ScalarMultKeyExtended(p *KeyExtended, scalar *Key) (result *KeyExtended) {
	var resultPoint ProjectiveGroupElement
	GeScalarMult(&resultPoint, scalar, p.Point)
	result = new(KeyExtended)
	result.Point = resultPoint.ToExtended()
	return
}
// multiply a scalar by H (second curve point of Pedersen Commitment)
func ScalarMultHExtended(scalar *Key) (result *KeyExtended) {
	h := new(ExtendedGroupElement)
	h.FromBytes(&H)
	resultPoint := new(ProjectiveGroupElement)
	GeScalarMult(resultPoint, scalar, h)
	result = new(KeyExtended)
	result.Point = resultPoint.ToExtended()
	return
}

// add two points together: sum = P1 + P2 using the full representation
func AddKeysExtended(sum, P1, P2 *KeyExtended) {
	a := P1.Point
	var b CachedGroupElement
	P2.Point.ToCached(&b)
	var c CompletedGroupElement
	geAdd(&c, a, &b)
	var tmp ExtendedGroupElement
	c.ToExtended(&tmp)
	sum.Point = &tmp
}

// compute a*G + b*B
func AddKeysExtended2(a, b *Key, B, result *KeyExtended) {
	BPoint := B.Point
	var RPoint ProjectiveGroupElement
	GeDoubleScalarMultVartime(&RPoint, b, BPoint, a)
	result.Point = RPoint.ToExtended()
	return
}

//addKeys3
//aAbB = a*A + b*B where a, b are scalars, A, B are curve points
//B must be input after applying "precomp"
func AddKeysExtended3(result *KeyExtended, a *Key, A *KeyExtended, b *Key, B_Precomputed *[8]CachedGroupElement) {
	var A_Point = A.Point

	var res ProjectiveGroupElement
	GeDoubleScalarMultPrecompVartime(&res, a, A_Point, b, B_Precomputed)
	result.Point = res.ToExtended()

}

//addKeys3_3  this is similiar to addkeys3 except it allows for use of precomputed A,B
//aAbB = a*A + b*B where a, b are scalars, A, B are curve points
//A,B must be input after applying "precomp"
func AddKeysExtended3_3(result *KeyExtended, a *Key, A_Precomputed *[8]CachedGroupElement, b *Key, B_Precomputed *[8]CachedGroupElement) {
	var res ProjectiveGroupElement
	GeDoubleScalarMultPrecompVartime2(&res, a, A_Precomputed, b, B_Precomputed)
	result.Point = res.ToExtended()

}

// subtract two points A - B
func SubKeysExtended(diff, k1, k2 *KeyExtended) {
	a := k1.Point
	b := new(CachedGroupElement)
	k2.Point.ToCached(b)
	c := new(CompletedGroupElement)
	geSub(c, a, b)
	c.ToExtended(diff.Point)
	return
}

// RandomPubKey takes a random scalar, interprets it as a point on the curve
//  remember the low order bug and do more auditing of the entire thing
func RandomPubKeyExtended() (result *KeyExtended) {
	result = new(KeyExtended)
	var p1 ProjectiveGroupElement
	var p2 CompletedGroupElement
	h := RandomScalar()
	p1.FromBytes(h)
	GeMul8(&p2, &p1)
	p2.ToExtended(result.Point)
	return
}

func MultiScalarMultKeyExtendedCached(AiLs [][8]CachedGroupElement, scalars []*Key, ) (result *KeyExtended) {
	r := new(ProjectiveGroupElement)

	digitsLs := make([][64]int8, len(scalars))
	for i:= range digitsLs {
		digitsLs[i] = scalars[i].SignedRadix16()
	}

	t := new(CompletedGroupElement)
	u := new(ExtendedGroupElement)

	r.Zero()
	cachedBase := new(ExtendedGroupElement)
	cur := new(CachedGroupElement)
	minusCur := new(CachedGroupElement)
	for i := 63; i >= 0; i-- {
		r.Double(t)
		t.ToProjective(r)
		r.Double(t)
		t.ToProjective(r)
		r.Double(t)
		t.ToProjective(r)
		r.Double(t)
		t.ToExtended(u)

		cachedBase.Zero()
		tmpt := new(CompletedGroupElement)
		for j:= 0; j < len(scalars); j++ {
			cur.Zero()
			b := digitsLs[j][i]
			bNegative := int8(negative(int32(b)))
			bAbs := b - (((-bNegative) & b) << 1)

			for k := int32(0); k < 8; k++ {
				if equal(int32(bAbs), k+1) == 1 { // optimisation
					CachedGroupElementCMove(cur, &AiLs[j][k], equal(int32(bAbs), k+1))
				}
			}
			FeCopy(&minusCur.yPlusX, &cur.yMinusX)
			FeCopy(&minusCur.yMinusX, &cur.yPlusX)
			FeCopy(&minusCur.Z, &cur.Z)
			FeNeg(&minusCur.T2d, &cur.T2d)
			CachedGroupElementCMove(cur, minusCur, int32(bNegative))

			geAdd(tmpt, cachedBase, cur)
			tmpt.ToExtended(cachedBase)
		}
		tmpv := new(CachedGroupElement)
		cachedBase.ToCached(tmpv)
		geAdd(t, u, tmpv)
		t.ToProjective(r)
	}
	result = new(KeyExtended)
	result.Point = r.ToExtended()
	return result
}

func MultiScalarMultKeyExtended(points []*KeyExtended, scalars []*Key) (result *KeyExtended) {
	r := new(ProjectiveGroupElement)


	pointLs := make([]ExtendedGroupElement, len(points))

	digitsLs := make([][64]int8, len(scalars))
	for i:= range digitsLs {
		digitsLs[i] = scalars[i].SignedRadix16()
	}

	AiLs := make([][8]CachedGroupElement, len(scalars))
	for i:= 0; i < len(scalars); i++ {
		// A,2A,3A,4A,5A,6A,7A,8A
		t := new(CompletedGroupElement)
		u := new(ExtendedGroupElement)
		pointLs[i] = *points[i].Point
		pointLs[i].ToCached(&AiLs[i][0])
		for j := 0; j < 7; j++ {
			geAdd(t, &pointLs[i], &AiLs[i][j])
			t.ToExtended(u)
			u.ToCached(&AiLs[i][j+1])
		}
	}

	t := new(CompletedGroupElement)
	u := new(ExtendedGroupElement)

	r.Zero()
	cachedBase := new(ExtendedGroupElement)
	cur := new(CachedGroupElement)
	minusCur := new(CachedGroupElement)
	for i := 63; i >= 0; i-- {
		r.Double(t)
		t.ToProjective(r)
		r.Double(t)
		t.ToProjective(r)
		r.Double(t)
		t.ToProjective(r)
		r.Double(t)
		t.ToExtended(u)

		cachedBase.Zero()
		tmpt := new(CompletedGroupElement)
		for j:= 0; j < len(scalars); j++ {
			cur.Zero()
			b := digitsLs[j][i]
			bNegative := int8(negative(int32(b)))
			bAbs := b - (((-bNegative) & b) << 1)

			for k := int32(0); k < 8; k++ {
				if equal(int32(bAbs), k+1) == 1 { // optimisation
					CachedGroupElementCMove(cur, &AiLs[j][k], equal(int32(bAbs), k+1))
				}
			}
			FeCopy(&minusCur.yPlusX, &cur.yMinusX)
			FeCopy(&minusCur.yMinusX, &cur.yPlusX)
			FeCopy(&minusCur.Z, &cur.Z)
			FeNeg(&minusCur.T2d, &cur.T2d)
			CachedGroupElementCMove(cur, minusCur, int32(bNegative))

			geAdd(tmpt, cachedBase, cur)
			tmpt.ToExtended(cachedBase)
		}
		tmpv := new(CachedGroupElement)
		cachedBase.ToCached(tmpv)
		geAdd(t, u, tmpv)
		t.ToProjective(r)
	}
	result = new(KeyExtended)
	result.Point = r.ToExtended()
	return result
}
