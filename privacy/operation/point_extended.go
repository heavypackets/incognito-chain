package operation

import (
	"crypto/subtle"
	C25519 "github.com/incognitochain/incognito-chain/privacy/operation/curve25519"
	"github.com/pkg/errors"
)

type PointExtended struct{
	key *C25519.KeyExtended
}

func (p *PointExtended) ToPoint() *Point {
	point := new(Point)
	point.key = p.ToBytes()
	return point
}

func (p *PointExtended) FromPoint(q *Point) *PointExtended {
	if p.key == nil {
		p.key = new(C25519.KeyExtended)
	}
	p.key.FromBytes(&q.key)

	return p
}

func RandomPointExtended() *PointExtended {
	sc := RandomScalar()
	return new(PointExtended).ScalarMultBase(sc)
}

func (p PointExtended) PointValid() bool {
	return true
}

//func (p Point) GetKey() C25519.Key {
//	return p.key
//}

//func (p *Point) SetKey(a *C25519.Key) (*Point, error) {
//	if p == nil {
//		p = new(Point)
//	}
//	p.key = *a
//
//	var point C25519.ExtendedGroupElement
//	if !point.FromBytes(&p.key) {
//		return nil, errors.New("Invalid point value")
//	}
//	return p, nil
//}

func (p *PointExtended) Set(q *PointExtended) *PointExtended {
	p.key = q.key
	return p
}

//func (p Point) MarshalText() []byte {
//	return []byte(fmt.Sprintf("%x", p.key[:]))
//}
//
//func (p *Point) UnmarshalText(data []byte) (*Point, error) {
//	if p == nil {
//		p = new(Point)
//	}
//
//	byteSlice, _ := hex.DecodeString(string(data))
//	if len(byteSlice) != Ed25519KeySize {
//		return nil, errors.New("Incorrect key size")
//	}
//	copy(p.key[:], byteSlice)
//	return p, nil
//}

func (p PointExtended) ToBytes() [Ed25519KeySize]byte {
	return p.key.ToBytes()
}

func (p PointExtended) ToBytesS() []byte {
	slice := p.key.ToBytes()
	return slice[:]
}

func (p *PointExtended) FromBytes(b *C25519.Key) (*PointExtended, error) {
	if p == nil {
		return nil, errors.New("Point receiver cannot be nil")
	}
	if p.key == nil {
		p.key = new(C25519.KeyExtended)
	}
	err := p.key.FromBytes(b)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (p *PointExtended) FromBytesS(b []byte) (*PointExtended, error) {
	if len(b) != Ed25519KeySize {
		return nil, errors.New("Invalid Ed25519 Key Size")
	}

	if p.key == nil{
		p.key = new(C25519.KeyExtended)
	}

	var array = new(C25519.Key)
	copy(array[:], b)
	err := p.key.FromBytes(array)

	if err != nil {
		return nil, err
	}

	return p, nil
}

func (p *PointExtended) Identity() *PointExtended {
	if p.key == nil {
		p.key = new(C25519.KeyExtended)
	}
	p.key.FromBytes(&C25519.Identity)
	return p
}

func (p PointExtended) IsIdentity() bool {
	if p.key.ToBytes() == C25519.Identity {
		return true
	}
	return false
}

// does a * G where a is a scalar and G is the curve basepoint
func (p *PointExtended) ScalarMultBase(a *Scalar) *PointExtended {
	if p.key == nil {
		p.key = new(C25519.KeyExtended)
	}
	key := C25519.ScalarMultBaseExtended(&a.key)
	p.key = key
	return p
}

func (p *PointExtended) ScalarMult(pa *PointExtended, a *Scalar) *PointExtended {
	if p.key == nil {
		p.key = new(C25519.KeyExtended)
	}
	key := C25519.ScalarMultKeyExtended(pa.key, &a.key)
	p.key = key
	return p
}

func (p *PointExtended) MultiScalarMultCached(scalarLs []*Scalar, pointPreComputedLs [][8]C25519.CachedGroupElement) *PointExtended {
	nSc := len(scalarLs)

	if nSc != len(pointPreComputedLs) {
		panic("Cannot MultiscalarMul with different size inputs")
	}

	scalarKeyLs := make([]*C25519.Key, nSc)
	for i := 0; i < nSc; i++ {
		scalarKeyLs[i] = &scalarLs[i].key
	}
	key := C25519.MultiScalarMultKeyExtendedCached(pointPreComputedLs, scalarKeyLs)
	res := new(PointExtended)
	res.key = key
	return res
}

func (p *PointExtended) MultiScalarMult(scalarLs []*Scalar, pointLs []*PointExtended) *PointExtended {
	nSc := len(scalarLs)
	nPoint := len(pointLs)

	if nSc != nPoint {
		panic("Cannot MultiscalarMul with different size inputs")
	}

	scalarKeyLs := make([]*C25519.Key, nSc)
	pointKeyLs := make([]*C25519.KeyExtended, nSc)
	for i := 0; i < nSc; i++ {
		scalarKeyLs[i] = &scalarLs[i].key
		pointKeyLs[i] = pointLs[i].key
	}
	key := C25519.MultiScalarMultKeyExtended(pointKeyLs, scalarKeyLs)
	res := new(PointExtended)
	res.key = key
	return res
}

func (p *PointExtended) InvertScalarMultBase(a *Scalar) *PointExtended {
	inv := new(Scalar).Invert(a)
	p.ScalarMultBase(inv)
	return p
}

func (p *PointExtended) InvertScalarMult(pa *PointExtended, a *Scalar) *PointExtended {
	inv := new(Scalar).Invert(a)
	p.ScalarMult(pa, inv)
	return p
}

func (p *PointExtended) Derive(pa *PointExtended, a *Scalar, b *Scalar) *PointExtended {
	c := new(Scalar).Add(a, b)
	return p.InvertScalarMult(pa, c)
}

func (p *PointExtended) Add(pa, pb *PointExtended) *PointExtended {
	if p.key == nil {
		p.key = new(C25519.KeyExtended)
	}
	res := p.key
	C25519.AddKeysExtended(res, pa.key, pb.key)
	p.key = res
	return p
}

// aA + bB
func (p *PointExtended) AddPedersen(a *Scalar, A *PointExtended, b *Scalar, B *PointExtended) *PointExtended {
	if p.key == nil {
		p.key = new(C25519.KeyExtended)
	}

	var A_Precomputed [8]C25519.CachedGroupElement
	Ae := new(C25519.ExtendedGroupElement)

	Ae = A.key.Point
	C25519.GePrecompute(&A_Precomputed, Ae)

	var B_Precomputed [8]C25519.CachedGroupElement
	Be := new(C25519.ExtendedGroupElement)
	Be = B.key.Point
	C25519.GePrecompute(&B_Precomputed, Be)

	key := new(C25519.KeyExtended)
	C25519.AddKeysExtended3_3(key, &a.key, &A_Precomputed, &b.key, &B_Precomputed)
	p.key = key
	return p
}

func (p *PointExtended) AddPedersenCached(a *Scalar, APreCompute [8]C25519.CachedGroupElement, b *Scalar, BPreCompute [8]C25519.CachedGroupElement) *PointExtended {
	key := new(C25519.KeyExtended)
	C25519.AddKeysExtended3_3(key, &a.key, &APreCompute, &b.key, &BPreCompute)
	p.key = key
	return p
}

func (p *PointExtended) Sub(pa, pb *PointExtended) *PointExtended {
	if p.key == nil {
		p.key = new(C25519.KeyExtended)
	}
	res := p.key
	C25519.SubKeysExtended(res, pa.key, pb.key)
	p.key = res
	return p
}

func IsPointExtendedEqual(pa *PointExtended, pb *PointExtended) bool {
	tmpa := pa.ToBytesS()
	tmpb := pb.ToBytesS()

	return subtle.ConstantTimeCompare(tmpa, tmpb) == 1
}

func HashToPointExtendedFromIndex(index int64, padStr string) *PointExtended {
	array := C25519.GBASE.ToBytes()
	msg := array[:]
	msg = append(msg, []byte(padStr)...)
	msg = append(msg, []byte(string(index))...)

	keyHash := C25519.Key(C25519.Keccak256(msg))
	keyPoint := new(C25519.KeyExtended)
	keyPoint.FromBytes(&keyHash)
	keyPoint = keyPoint.HashToPoint()

	point := new(PointExtended)
	point.key = keyPoint

	return point
}

func HashToPointExtended(b []byte) *PointExtended {
	keyHash := C25519.Key(C25519.Keccak256(b))
	keyPoint := new(C25519.KeyExtended)
	keyPoint.FromBytes(&keyHash)
	keyPoint = keyPoint.HashToPoint()

	point := new(PointExtended)
	point.key = keyPoint


	return point
}