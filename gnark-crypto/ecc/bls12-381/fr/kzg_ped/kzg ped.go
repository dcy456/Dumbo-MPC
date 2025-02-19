// Copyright 2020 Consensys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,cd
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by consensys/gnark-crypto DO NOT EDIT

package kzg_ped

import (
	"C"
	"crypto/sha256"
	"errors"

	"hash"
	"math/big"
	"sync"

	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/internal/parallel"
)

var (
	ErrInvalidNbDigests              = errors.New("number of digests is not the same as the number of polynomials")
	ErrZeroNbDigests                 = errors.New("number of digests is zero")
	ErrInvalidPolynomialSize         = errors.New("invalid polynomial size (larger than SRS or == 0)")
	ErrVerifyOpeningProof            = errors.New("can't verify opening proof")
	ErrVerifyBatchOpeningSinglePoint = errors.New("can't verify batch opening proof at single point")
	ErrMinSRSSize                    = errors.New("minimum srs size is 2")
)

// Digest commitment of a polynomial.
type Digest = curve.G1Affine

// ProvingKey used to create or open commitments
type ProvingKey struct {
	G1_g []curve.G1Affine // [G₁_g [α]G₁_g , [α²]G₁_g, ... ]
	G1_h []curve.G1Affine // [G₁_h [α]G₁_h , [α²]G₁_h, ... ]
}

// VerifyingKey used to verify opening proofs
type VerifyingKey struct {
	G2   [2]curve.G2Affine // [G₂, [α]G₂ ]
	G1_g curve.G1Affine
	G1_h curve.G1Affine
}

// SRS must be computed through MPC and comprises the ProvingKey and the VerifyingKey
type SRS struct {
	Pk ProvingKey
	Vk VerifyingKey
}

// NewSRS returns a new SRS using alpha as randomness source
//
// In production, a SRS generated through MPC should be used.
//
// implements io.ReaderFrom and io.WriterTo
func NewSRS(size uint64, bAlpha *big.Int) (*SRS, error) {

	if size < 2 {
		return nil, ErrMinSRSSize
	}
	var srs SRS
	srs.Pk.G1_g = make([]curve.G1Affine, size)
	srs.Pk.G1_h = make([]curve.G1Affine, size)

	var alpha fr.Element
	alpha.SetBigInt(bAlpha)

	_, _, gen1_gAff, gen2Aff := curve.Generators()
	srs.Pk.G1_g[0] = gen1_gAff
	srs.Vk.G1_g = gen1_gAff
	_, _, gen1_hAff, _ := curve.Generators()
	srs.Pk.G1_h[0] = gen1_hAff
	srs.Vk.G1_h = gen1_hAff

	srs.Vk.G2[0] = gen2Aff
	srs.Vk.G2[1].ScalarMultiplication(&gen2Aff, bAlpha)

	alphas := make([]fr.Element, size-1)
	alphas[0] = alpha
	for i := 1; i < len(alphas); i++ {
		alphas[i].Mul(&alphas[i-1], &alpha)
	}
	g1s := curve.BatchScalarMultiplicationG1(&gen1_gAff, alphas)
	copy(srs.Pk.G1_g[1:], g1s)
	hs := curve.BatchScalarMultiplicationG1(&gen1_hAff, alphas)
	copy(srs.Pk.G1_h[1:], hs)

	return &srs, nil
}

// OpeningProof KZG proof for opening at a single point.
//
// implements io.ReaderFrom and io.WriterTo
type OpeningProof struct {
	// H quotient polynomial (f - f(z))/(x-z)
	H curve.G1Affine

	// ClaimedValue purported value
	ClaimedValue fr.Element

	// ClaimedValue purported value
	ClaimedValueAux fr.Element
}

// BatchOpeningProof opening proof for many polynomials at the same point
//
// implements io.ReaderFrom and io.WriterTo
type BatchOpeningProof struct {
	// H quotient polynomial Sum_i gamma**i*(f - f(z))/(x-z)
	H curve.G1Affine

	// ClaimedValues purported values
	ClaimedValues    []fr.Element
	ClaimedValuesAux []fr.Element
}

type Triples struct {
	A []fr.Element
	B []fr.Element
	C []fr.Element
}

// Commit commits to a polynomial using a multi exponentiation with the SRS.
// It is assumed that the polynomial is in canonical form, in Montgomery form.
func Commit(p []fr.Element, p_aux []fr.Element, pk ProvingKey, nbTasks ...int) (Digest, error) {

	if len(p) == 0 || len(p) > len(pk.G1_g) {
		return Digest{}, ErrInvalidPolynomialSize
	}

	var res curve.G1Affine

	config := ecc.MultiExpConfig{}
	if len(nbTasks) > 0 {
		config.NbTasks = nbTasks[0]
	}
	if _, err := res.MultiExp(pk.G1_g[:len(p)], p, config); err != nil {
		return Digest{}, err
	}

	var res_aux curve.G1Affine
	config_aux := ecc.MultiExpConfig{}
	if len(nbTasks) > 0 {
		config_aux.NbTasks = nbTasks[0]
	}
	if _, err := res_aux.MultiExp(pk.G1_h[:len(p_aux)], p_aux, config_aux); err != nil {
		return Digest{}, err
	}

	var G1_gJac curve.G1Jac
	G1_gJac.FromAffine(&res)

	var G1_hJac curve.G1Jac
	G1_hJac.FromAffine(&res_aux)
	G1_gJac.AddAssign(&G1_hJac)

	res.FromJacobian(&G1_gJac)

	return res, nil
}

// TODO @Tabaie get rid of this and use the polynomial package
// eval returns p(point) where p is interpreted as a polynomial
// ∑_{i<len(p)}p[i]Xⁱ, ∑_{i<len(p_aux)}p_aux[i]Xⁱ
func Eval(p []fr.Element, p_aux []fr.Element, point fr.Element) (fr.Element, fr.Element) {
	var res_p fr.Element
	n := len(p)
	res_p.Set(&p[n-1])
	for i := n - 2; i >= 0; i-- {
		res_p.Mul(&res_p, &point).Add(&res_p, &p[i])
	}

	var res_p_aux fr.Element
	res_p_aux.Set(&p_aux[n-1])
	for i := n - 2; i >= 0; i-- {
		res_p_aux.Mul(&res_p_aux, &point).Add(&res_p_aux, &p_aux[i])
	}
	return res_p, res_p_aux
}

// Open computes an opening proof of polynomial p at given point.
// fft.Domain Cardinality must be larger than p.Degree()
func Open(p []fr.Element, p_aux []fr.Element, point fr.Element, pk ProvingKey) (OpeningProof, error) {
	if len(p) == 0 || len(p) > len(pk.G1_g) {
		return OpeningProof{}, ErrInvalidPolynomialSize
	}

	// build the proof
	p_a, p_aux_a := Eval(p, p_aux, point)

	res := OpeningProof{
		ClaimedValue:    p_a,
		ClaimedValueAux: p_aux_a,
	}
	// compute H
	// h reuses memory from _p
	_p := make([]fr.Element, len(p))

	copy(_p, p)
	h := dividePolyByXminusA(_p, res.ClaimedValue, point)

	// compute H
	// h reuses memory from _p
	_paux := make([]fr.Element, len(p_aux))
	copy(_paux, p_aux)
	h_aux := dividePolyByXminusA(_paux, res.ClaimedValueAux, point)

	// commit to H
	hCommit, err := Commit(h, h_aux, pk)
	if err != nil {
		return OpeningProof{}, err
	}
	res.H.Set(&hCommit)

	return res, nil
}

// Open computes an opening proof of polynomial p at given point.
// fft.Domain Cardinality must be larger than p.Degree()
func OpenZero(p []fr.Element, p_aux []fr.Element, pk ProvingKey) (OpeningProof, error) {
	if len(p) == 0 || len(p) > len(pk.G1_g) {
		return OpeningProof{}, ErrInvalidPolynomialSize
	}

	// build the proof
	var point fr.Element
	point.SetZero()
	p_0, p_aux_0 := p[0], p_aux[0]
	res := OpeningProof{
		ClaimedValue:    p_0,
		ClaimedValueAux: p_aux_0,
	}

	// compute H
	// h reuses memory from _p
	_p := make([]fr.Element, len(p))
	copy(_p, p)
	h := dividePolyByXminusA(_p, res.ClaimedValue, point)
	_paux := make([]fr.Element, len(p_aux))
	copy(_paux, p_aux)
	h_aux := dividePolyByXminusA(_paux, res.ClaimedValueAux, point)

	// commit to H
	hCommit, err := Commit(h, h_aux, pk)
	if err != nil {
		return OpeningProof{}, err
	}
	res.H.Set(&hCommit)

	return res, nil
}

// dividePolyByXminusA computes (f-f(a))/(x-a), in canonical basis, in regular form
// f memory is re-used for the result
func dividePolyByXminusA(f []fr.Element, fa, a fr.Element) []fr.Element {

	// first we compute f-f(a)
	f[0].Sub(&f[0], &fa)
	// now we use synthetic division to divide by x-a
	var t fr.Element
	for i := len(f) - 2; i >= 0; i-- {
		t.Mul(&f[i+1], &a)

		f[i].Add(&f[i], &t)
	}
	// the result is of degree deg(f)-1
	return f[1:]
}

func Verify(commitment *Digest, proof *OpeningProof, point fr.Element, vk VerifyingKey) bool {

	// [f(a)]G₁
	var claimedValueG1Aff curve.G1Jac
	var claimedValueBigInt big.Int
	proof.ClaimedValue.BigInt(&claimedValueBigInt)
	claimedValueG1Aff.ScalarMultiplicationAffine(&vk.G1_g, &claimedValueBigInt)

	// [f_aux(a)]G₁
	var claimedValueAuxG1Aff curve.G1Jac
	var claimedValueAuxBigInt big.Int
	proof.ClaimedValueAux.BigInt(&claimedValueAuxBigInt)
	claimedValueAuxG1Aff.ScalarMultiplicationAffine(&vk.G1_h, &claimedValueAuxBigInt)

	// [f(a)]G₁ + [f_aux(a)]G₁
	claimedValueG1Aff.AddAssign(&claimedValueAuxG1Aff)

	// [f(α) - f(a)]G₁
	var fminusfaG1Jac curve.G1Jac
	fminusfaG1Jac.FromAffine(commitment)
	fminusfaG1Jac.SubAssign(&claimedValueG1Aff)

	// [-H(α)]G₁
	var negH curve.G1Affine
	negH.Neg(&proof.H)

	// [f(α) - f(a) + a*H(α)]G₁
	var totalG1 curve.G1Jac
	var pointBigInt big.Int
	point.BigInt(&pointBigInt)
	totalG1.ScalarMultiplicationAffine(&proof.H, &pointBigInt)
	totalG1.AddAssign(&fminusfaG1Jac)
	var totalG1Aff curve.G1Affine
	totalG1Aff.FromJacobian(&totalG1)

	// e([f(α)-f(a)+aH(α)]G₁], G₂).e([-H(α)]G₁, [α]G₂) == 1
	check, err := curve.PairingCheck(
		[]curve.G1Affine{totalG1Aff, negH},
		[]curve.G2Affine{vk.G2[0], vk.G2[1]},
	)
	// fmt.Println(check)
	if err != nil {
		return check
	}
	if !check {
		return check
	}
	return check
}

type ZeroKnowledgeOpeningProof struct {
	// H quotient polynomial (f - f(z))/(x-z)
	H curve.G1Affine

	// ClaimedValue purported value
	CommittedValue curve.G1Affine
}

func HiddenVerify(commitment *Digest, proof *ZeroKnowledgeOpeningProof, point fr.Element, vk VerifyingKey) bool {

	var committedValueG1Aff curve.G1Jac
	committedValueG1Aff.FromAffine(&proof.CommittedValue)

	// [f(α) - f(a)]G₁
	var fminusfaG1Jac curve.G1Jac
	fminusfaG1Jac.FromAffine(commitment)
	fminusfaG1Jac.SubAssign(&committedValueG1Aff)

	// [-H(α)]G₁
	var negH curve.G1Affine
	negH.Neg(&proof.H)

	// [f(α) - f(a) + a*H(α)]G₁
	var totalG1 curve.G1Jac
	var pointBigInt big.Int
	point.BigInt(&pointBigInt)
	totalG1.ScalarMultiplicationAffine(&proof.H, &pointBigInt)
	totalG1.AddAssign(&fminusfaG1Jac)
	var totalG1Aff curve.G1Affine
	totalG1Aff.FromJacobian(&totalG1)

	// e([f(α)-f(a)+aH(α)]G₁], G₂).e([-H(α)]G₁, [α]G₂) == 1
	check, err := curve.PairingCheck(
		[]curve.G1Affine{totalG1Aff, negH},
		[]curve.G2Affine{vk.G2[0], vk.G2[1]},
	)
	// fmt.Println(check)
	if err != nil {
		return check
	}
	if !check {
		return check
	}
	return check
}

// deriveGamma derives a challenge using Fiat Shamir to fold proofs.
func Derivechall(digests []curve.G1Affine, hf hash.Hash) (fr.Element, error) {

	// derive the challenge gamma, binded to the point and the commitments
	fs := fiatshamir.NewTranscript(hf, "challenge")
	for i := range digests {
		if err := fs.Bind("challenge", digests[i].Marshal()); err != nil {
			return fr.Element{}, err
		}
	}
	gammaByte, err := fs.ComputeChallenge("challenge")
	if err != nil {
		return fr.Element{}, err
	}
	var gamma fr.Element
	gamma.SetBytes(gammaByte)

	return gamma, nil
}

type ProdProof struct {
	G1proofs []curve.G1Affine

	Frproofs []fr.Element
}

// prodproofs:
// beta, gamma, delta: prodproofs.G1proofs[0], prodproofs.G1proofs[1], prodproofs.G1proofs[2]
// z[1], ..., z[5]: prodproofs.Frproofs[0], ..., prodproofs.Frproofs[4]
func Prodproof(srs_pk ProvingKey, a fr.Element, a_aux fr.Element, b fr.Element, b_aux fr.Element,
	c fr.Element, c_aux fr.Element, T_a curve.G1Affine, T_b curve.G1Affine, T_c curve.G1Affine) ProdProof {
	// g := srs_pk.G1_g[0]
	// h := srs_pk.G1_h[0]
	gh := make([]curve.G1Affine, 2)
	gh[0].Set(&srs_pk.G1_g[0])
	gh[1].Set(&srs_pk.G1_h[0])
	e := make([]fr.Element, 5)
	for i := 0; i < 5; i++ {
		e[i].SetRandom()
	}

	var test_c fr.Element
	test_c.Mul(&a, &b)

	if !test_c.Equal(&c) {
		fmt.Println("test_c not equals to c")
	}

	// proofs[0]: beta
	// proofs[1]: gamma
	// proofs[2]: delat
	e_list := make([]fr.Element, 2)
	proofs := make([]curve.G1Affine, 3)
	e_list[0].Set(&e[0])
	e_list[1].Set(&e[1])
	proofs[0].MultiExp(gh, e_list, ecc.MultiExpConfig{})

	e_list[0].Set(&e[2])
	e_list[1].Set(&e[3])
	proofs[1].MultiExp(gh, e_list, ecc.MultiExpConfig{})

	gh[0].Set(&T_a)
	e_list[0].Set(&e[2])
	e_list[1].Set(&e[4])
	proofs[2].MultiExp(gh, e_list, ecc.MultiExpConfig{})

	hf := sha256.New()
	transcript, err := Derivechall(proofs, hf)
	if err != nil {
		fmt.Println(err)
	}

	z := make([]fr.Element, 5)
	z[0].Mul(&transcript, &a)
	z[0].Add(&z[0], &e[0])

	z[1].Mul(&transcript, &a_aux)
	z[1].Add(&z[1], &e[1])

	z[2].Mul(&transcript, &b)
	z[2].Add(&z[2], &e[2])

	z[3].Mul(&transcript, &b_aux)
	z[3].Add(&z[3], &e[3])

	z[4].Mul(&a_aux, &b)
	z[4].Sub(&c_aux, &z[4])
	z[4].Mul(&transcript, &z[4])
	z[4].Add(&z[4], &e[4])

	var prodproofs ProdProof
	prodproofs.G1proofs = make([]curve.G1Affine, 3)
	prodproofs.Frproofs = make([]fr.Element, 5)
	copy(prodproofs.G1proofs, proofs)
	copy(prodproofs.Frproofs, z)

	return prodproofs
}

func Prodproofverify(srs_vk VerifyingKey, prodproof ProdProof, T_a curve.G1Affine, T_b curve.G1Affine, T_c curve.G1Affine) bool {

	computerightside := func(g curve.G1Affine, h curve.G1Affine, frproofs []fr.Element, i int, j int) curve.G1Affine {

		z_list := make([]fr.Element, 2)
		z_list[0].Set(&frproofs[i])
		z_list[1].Set(&frproofs[j])

		gh := make([]curve.G1Affine, 2)
		gh[0].Set(&g)
		gh[1].Set(&h)
		var res curve.G1Affine

		res.MultiExp(gh, z_list, ecc.MultiExpConfig{})
		return res
	}

	rightside := make([]curve.G1Affine, 3)
	rightside[0] = computerightside(srs_vk.G1_g, srs_vk.G1_h, prodproof.Frproofs, 0, 1)
	rightside[1] = computerightside(srs_vk.G1_g, srs_vk.G1_h, prodproof.Frproofs, 2, 3)
	rightside[2] = computerightside(T_a, srs_vk.G1_h, prodproof.Frproofs, 2, 4)


	computeleftside := func(T curve.G1Affine, g1proofs curve.G1Affine, transcript []fr.Element) curve.G1Affine {
		var res curve.G1Affine

		g1_list := make([]curve.G1Affine, 1)
		g1_list[0].Set(&T)

		res.MultiExp(g1_list, transcript, ecc.MultiExpConfig{})
		res.Add(&g1proofs, &res)
		return res
	}


	hf := sha256.New()
	transcript, err := Derivechall(prodproof.G1proofs, hf)
	if err != nil {
		fmt.Println(err)
	}


	transcriptlist := make([]fr.Element, 1)
	transcriptlist[0].Set(&transcript)

	leftside := make([]curve.G1Affine, 3)

	leftside[0] = computeleftside(T_a, prodproof.G1proofs[0], transcriptlist)
	leftside[1] = computeleftside(T_b, prodproof.G1proofs[1], transcriptlist)
	leftside[2] = computeleftside(T_c, prodproof.G1proofs[2], transcriptlist)


	for i := 0; i < 3; i++ {
		if !leftside[i].Equal(&rightside[i]) {
			fmt.Println("Product check successful!", i)
			return false
		}
	}

	return true
}
func BatchProductVerify(srs_vk VerifyingKey, prodproof []ProdProof, 
	zk_proof_ab []curve.G1Affine, zk_proof_c_zero []curve.G1Affine) bool {
	batchsize := len(prodproof)
	if batchsize != len(zk_proof_ab)/2 {
		fmt.Println("Error length of Hidden evaluation of ab!")
		if batchsize != len(zk_proof_c_zero) {
			fmt.Println("Error length of Hidden evaluation of c!")
		}
	}

	hf := sha256.New()
	transcript := make([]fr.Element, batchsize)
	for i := 0; i < batchsize; i++ {
		transcript[i], _ = Derivechall(prodproof[i].G1proofs, hf)
	}

	// leftside batch computation
	leftside_base := make([][]curve.G1Affine, 3)
	leftside_exponential := make([][]fr.Element, 3)
	for i := 0; i < 3; i++ {
		leftside_base[i] = make([]curve.G1Affine, 2*batchsize)
		leftside_exponential[i] = make([]fr.Element, 2*batchsize)
	}

	for i := 0; i < batchsize; i++ {
		j := i * 2
		leftside_base[0][j].Set(&prodproof[i].G1proofs[0])
		leftside_base[0][j+1].Set(&zk_proof_ab[i])
		leftside_exponential[0][j].SetOne()
		leftside_exponential[0][j+1].Set(&transcript[i])
	}

	for i := 0; i < batchsize; i++ {
		j := i * 2
		leftside_base[1][j].Set(&prodproof[i].G1proofs[1])
		leftside_base[1][j+1].Set(&zk_proof_ab[i+batchsize])
		leftside_exponential[1][j].SetOne()
		leftside_exponential[1][j+1].Set(&transcript[i])
	}

	for i := 0; i < batchsize; i++ {
		j := i * 2
		leftside_base[2][j].Set(&prodproof[i].G1proofs[2])
		leftside_base[2][j+1].Set(&zk_proof_c_zero[i])
		leftside_exponential[2][j].SetOne()
		leftside_exponential[2][j+1].Set(&transcript[i])
	}

	leftside := make([]curve.G1Affine, 3)

	for i := 0; i < 3; i++ {
		leftside[i].MultiExp(leftside_base[i], leftside_exponential[i], ecc.MultiExpConfig{})
	}

	// rightside batch computation
	rightside_base := make([]curve.G1Affine, 2*batchsize)
	rightside_exponential := make([][]fr.Element, 23)
	for i := 0; i < 2; i++ {
		rightside_exponential[i] = make([]fr.Element, 2*batchsize)
	}

	for i := 0; i < batchsize; i++ {
		j := i * 2
		rightside_base[j].Set(&srs_vk.G1_g)
		rightside_base[j+1].Set(&srs_vk.G1_h)
	}

	for i := 0; i < batchsize; i++ {
		j := i * 2
		rightside_exponential[0][j].Set(&prodproof[i].Frproofs[0])
		rightside_exponential[0][j+1].Set(&prodproof[i].Frproofs[1])
		rightside_exponential[1][j].Set(&prodproof[i].Frproofs[2])
		rightside_exponential[1][j+1].Set(&prodproof[i].Frproofs[3])
	}

	rightside := make([]curve.G1Affine, 3)
	for i := 0; i < 2; i++ {
		rightside[i].MultiExp(rightside_base, rightside_exponential[i], ecc.MultiExpConfig{})
	}

	// 复用了rightside_base,rightside_exponential[1]作为rightside_base[2],rightside_exponential[2]
	for i := 0; i < batchsize; i++ {
		j := i * 2
		rightside_base[j].Set(&zk_proof_ab[i])
		rightside_exponential[1][j+1].Set(&prodproof[i].Frproofs[4])
	}

	rightside[2].MultiExp(rightside_base, rightside_exponential[1], ecc.MultiExpConfig{})

	for i := 0; i < 3; i++ {
		if !leftside[i].Equal(&rightside[i]) {
			fmt.Println("Product check fails!", i)
			return false
		}
	}

	return true
}

// func BatchProductVerify(srs_vk VerifyingKey, prodproof []ProdProof, zk_proof_ab []ZeroKnowledgeOpeningProof, zk_proof_c_zero []ZeroKnowledgeOpeningProof) bool {
// 	batchsize := len(prodproof)
// 	if batchsize != len(zk_proof_ab)/2 {
// 		fmt.Println("Error length of Hidden evaluation of ab!")
// 		if batchsize != len(zk_proof_c_zero) {
// 			fmt.Println("Error length of Hidden evaluation of c!")
// 		}
// 	}

// 	hf := sha256.New()
// 	transcript := make([]fr.Element, batchsize)
// 	for i := 0; i < batchsize; i++ {
// 		transcript[i], _ = Derivechall(prodproof[i].G1proofs, hf)
// 	}

// 	// leftside batch computation
// 	leftside_base := make([][]curve.G1Affine, 3)
// 	leftside_exponential := make([][]fr.Element, 3)
// 	for i := 0; i < 3; i++ {
// 		leftside_base[i] = make([]curve.G1Affine, 2*batchsize)
// 		leftside_exponential[i] = make([]fr.Element, 2*batchsize)
// 	}

// 	for i := 0; i < batchsize; i++ {
// 		j := i * 2
// 		leftside_base[0][j].Set(&prodproof[i].G1proofs[0])
// 		leftside_base[0][j+1].Set(&zk_proof_ab[i].CommittedValue)
// 		leftside_exponential[0][j].SetOne()
// 		leftside_exponential[0][j+1].Set(&transcript[i])
// 	}

// 	for i := 0; i < batchsize; i++ {
// 		j := i * 2
// 		leftside_base[1][j].Set(&prodproof[i].G1proofs[1])
// 		leftside_base[1][j+1].Set(&zk_proof_ab[i+batchsize].CommittedValue)
// 		leftside_exponential[1][j].SetOne()
// 		leftside_exponential[1][j+1].Set(&transcript[i])
// 	}

// 	for i := 0; i < batchsize; i++ {
// 		j := i * 2
// 		leftside_base[2][j].Set(&prodproof[i].G1proofs[2])
// 		leftside_base[2][j+1].Set(&zk_proof_c_zero[i].CommittedValue)
// 		leftside_exponential[2][j].SetOne()
// 		leftside_exponential[2][j+1].Set(&transcript[i])
// 	}

// 	leftside := make([]curve.G1Affine, 3)

// 	for i := 0; i < 3; i++ {
// 		leftside[i].MultiExp(leftside_base[i], leftside_exponential[i], ecc.MultiExpConfig{})
// 	}

// 	// rightside batch computation
// 	rightside_base := make([]curve.G1Affine, 2*batchsize)
// 	rightside_exponential := make([][]fr.Element, 23)
// 	for i := 0; i < 2; i++ {
// 		rightside_exponential[i] = make([]fr.Element, 2*batchsize)
// 	}

// 	for i := 0; i < batchsize; i++ {
// 		j := i * 2
// 		rightside_base[j].Set(&srs_vk.G1_g)
// 		rightside_base[j+1].Set(&srs_vk.G1_h)
// 	}

// 	for i := 0; i < batchsize; i++ {
// 		j := i * 2
// 		rightside_exponential[0][j].Set(&prodproof[i].Frproofs[0])
// 		rightside_exponential[0][j+1].Set(&prodproof[i].Frproofs[1])
// 		rightside_exponential[1][j].Set(&prodproof[i].Frproofs[2])
// 		rightside_exponential[1][j+1].Set(&prodproof[i].Frproofs[3])
// 	}

// 	rightside := make([]curve.G1Affine, 3)
// 	for i := 0; i < 2; i++ {
// 		rightside[i].MultiExp(rightside_base, rightside_exponential[i], ecc.MultiExpConfig{})
// 	}

// 	// 复用了rightside_base,rightside_exponential[1]作为rightside_base[2],rightside_exponential[2]
// 	for i := 0; i < batchsize; i++ {
// 		j := i * 2
// 		rightside_base[j].Set(&zk_proof_ab[i].CommittedValue)
// 		rightside_exponential[1][j+1].Set(&prodproof[i].Frproofs[4])
// 	}

// 	rightside[2].MultiExp(rightside_base, rightside_exponential[1], ecc.MultiExpConfig{})

// 	for i := 0; i < 3; i++ {
// 		if !leftside[i].Equal(&rightside[i]) {
// 			fmt.Println("Product check fails!", i)
// 			return false
// 		}
// 	}

// 	return true
// }

// BatchOpenSinglePoint creates a batch opening proof at point of a list of polynomials.
// It's an interactive protocol, made non-interactive using Fiat Shamir.
//
// * point is the point at which the polynomials are opened.
// * digests is the list of committed polynomials to open, need to derive the challenge using Fiat Shamir.
// * polynomials is the list of polynomials to open, they are supposed to be of the same size.
func BatchOpenSinglePoint(polynomials [][]fr.Element, polynomials_aux [][]fr.Element, digests []Digest, point fr.Element, hf hash.Hash, pk ProvingKey) (BatchOpeningProof, error) {

	// check for invalid sizes

	// check for invalid sizes
	nbDigests := len(digests)
	if nbDigests != len(polynomials) {
		return BatchOpeningProof{}, ErrInvalidNbDigests
	}

	// TODO ensure the polynomials are of the same size
	largestPoly := -1
	for _, p := range polynomials {
		if len(p) == 0 || len(p) > len(pk.G1_g) {
			return BatchOpeningProof{}, ErrInvalidPolynomialSize
		}
		if len(p) > largestPoly {
			largestPoly = len(p)
		}
	}

	var res BatchOpeningProof

	// compute the purported values
	res.ClaimedValues = make([]fr.Element, len(polynomials))
	res.ClaimedValuesAux = make([]fr.Element, len(polynomials))
	var wg sync.WaitGroup
	wg.Add(len(polynomials))
	for i := 0; i < len(polynomials); i++ {
		go func(_i int) {
			res.ClaimedValues[_i], res.ClaimedValuesAux[_i] = Eval(polynomials[_i], polynomials_aux[_i], point)
			wg.Done()
		}(i)
	}

	// wait for polynomial evaluations to be completed (res.ClaimedValues)
	wg.Wait()

	// derive the challenge γ, binded to the point and the commitments
	gamma, err := deriveGamma(point, digests, res.ClaimedValues, res.ClaimedValuesAux, hf)
	if err != nil {
		return BatchOpeningProof{}, err
	}

	// ∑ᵢγⁱf(a), ∑ᵢγⁱf_aux(a)
	var foldedEvaluations fr.Element
	var foldedEvaluationsAux fr.Element
	chSumGammai := make(chan struct{}, 1)
	go func() {
		foldedEvaluations = res.ClaimedValues[nbDigests-1]
		foldedEvaluationsAux = res.ClaimedValuesAux[nbDigests-1]
		for i := nbDigests - 2; i >= 0; i-- {
			foldedEvaluations.Mul(&foldedEvaluations, &gamma).
				Add(&foldedEvaluations, &res.ClaimedValues[i])
			foldedEvaluationsAux.Mul(&foldedEvaluationsAux, &gamma).
				Add(&foldedEvaluationsAux, &res.ClaimedValuesAux[i])
		}
		close(chSumGammai)
	}()

	// // ∑ᵢγⁱf_aux(a)
	// var foldedEvaluationsAux fr.Element
	// chSumGammai := make(chan struct{}, 1)
	// go func() {
	// 	foldedEvaluationsAux = res.ClaimedValuesAux[nbDigests-1]
	// 	for i := nbDigests - 2; i >= 0; i-- {
	// 		foldedEvaluationsAux.Mul(&foldedEvaluationsAux, &gamma).
	// 			Add(&foldedEvaluationsAux, &res.ClaimedValuesAux[i])
	// 	}
	// 	close(chSumGammai)
	// }()

	// compute ∑ᵢγⁱfᵢ
	// note: if we are willing to parallelize that, we could clone the poly and scale them by
	// gamma n in parallel, before reducing into foldedPolynomials
	foldedPolynomials := make([]fr.Element, largestPoly)
	copy(foldedPolynomials, polynomials[0])
	foldedPolynomialsAux := make([]fr.Element, largestPoly)
	copy(foldedPolynomialsAux, polynomials_aux[0])
	gammas := make([]fr.Element, len(polynomials_aux))
	gammas[0] = gamma
	for i := 1; i < len(polynomials); i++ {
		gammas[i].Mul(&gammas[i-1], &gamma)
	}

	for i := 1; i < len(polynomials); i++ {
		i := i
		parallel.Execute(len(polynomials[i]), func(start, end int) {
			var pj fr.Element
			for j := start; j < end; j++ {
				pj.Mul(&polynomials[i][j], &gammas[i-1])
				foldedPolynomials[j].Add(&foldedPolynomials[j], &pj)
			}
		})

		parallel.Execute(len(polynomials_aux[i]), func(start, end int) {
			var pj fr.Element
			for j := start; j < end; j++ {
				pj.Mul(&polynomials_aux[i][j], &gammas[i-1])
				foldedPolynomialsAux[j].Add(&foldedPolynomialsAux[j], &pj)
			}
		})
	}

	// compute H
	<-chSumGammai
	h := dividePolyByXminusA(foldedPolynomials, foldedEvaluations, point)
	foldedPolynomials = nil // same memory as h

	h_aux := dividePolyByXminusA(foldedPolynomialsAux, foldedEvaluationsAux, point)
	foldedPolynomials = nil // same memory as h

	res.H, err = Commit(h, h_aux, pk)
	if err != nil {
		return BatchOpeningProof{}, err
	}

	return res, nil
}

// deriveGamma derives a challenge using Fiat Shamir to fold proofs.
func deriveGamma(point fr.Element, digests []Digest, claimedValues []fr.Element, claimedValuesAux []fr.Element, hf hash.Hash) (fr.Element, error) {

	// derive the challenge gamma, binded to the point and the commitments
	fs := fiatshamir.NewTranscript(hf, "gamma")
	if err := fs.Bind("gamma", point.Marshal()); err != nil {
		return fr.Element{}, err
	}
	for i := range digests {
		if err := fs.Bind("gamma", digests[i].Marshal()); err != nil {
			return fr.Element{}, err
		}
	}
	for i := range claimedValues {
		if err := fs.Bind("gamma", claimedValues[i].Marshal()); err != nil {
			return fr.Element{}, err
		}
	}
	for i := range claimedValuesAux {
		if err := fs.Bind("gamma", claimedValuesAux[i].Marshal()); err != nil {
			return fr.Element{}, err
		}
	}
	gammaByte, err := fs.ComputeChallenge("gamma")
	if err != nil {
		return fr.Element{}, err
	}
	var gamma fr.Element
	gamma.SetBytes(gammaByte)

	return gamma, nil
}

// deriveGamma derives a challenge using Fiat Shamir to fold proofs.
func DeriveGamma_witness(point fr.Element, digests []Digest, committedValues []curve.G1Affine, hf hash.Hash) (fr.Element, error) {

	// derive the challenge gamma, binded to the point and the commitments
	fs := fiatshamir.NewTranscript(hf, "gamma")
	if err := fs.Bind("gamma", point.Marshal()); err != nil {
		return fr.Element{}, err
	}
	for i := range digests {
		if err := fs.Bind("gamma", digests[i].Marshal()); err != nil {
			return fr.Element{}, err
		}
	}
	for i := range committedValues {
		if err := fs.Bind("gamma", committedValues[i].Marshal()); err != nil {
			return fr.Element{}, err
		}
	}
	gammaByte, err := fs.ComputeChallenge("gamma")
	if err != nil {
		return fr.Element{}, err
	}
	var gamma fr.Element
	gamma.SetBytes(gammaByte)

	return gamma, nil
}

func Foldwit(point fr.Element, com []Digest, hidden_eval []curve.G1Affine, length int, wit []curve.G1Affine) curve.G1Affine {

	hf := sha256.New()
	gamma_ab, _ := DeriveGamma_witness(point, com, hidden_eval, hf)

	gammas := make([]fr.Element, length)
	gammas[0] = gamma_ab
	for i := 1; i < length; i++ {
		gammas[i].Mul(&gammas[i-1], &gamma_ab)
	}

	var foldwit curve.G1Affine
	foldwit.MultiExp(wit, gammas, ecc.MultiExpConfig{})

	return foldwit

}

func Foldcom_hiddeneval(point fr.Element, com []Digest, hidden_eval []curve.G1Affine) (curve.G1Affine, curve.G1Affine) {

	hf := sha256.New()
	gamma_ab, _ := DeriveGamma_witness(point, com, hidden_eval, hf)

	length := len(com)
	gammas := make([]fr.Element, length)
	gammas[0] = gamma_ab
	for i := 1; i < length; i++ {
		gammas[i].Mul(&gammas[i-1], &gamma_ab)
	}

	var foldcom curve.G1Affine
	foldcom.MultiExp(com, gammas, ecc.MultiExpConfig{})

	var foldhiddeneval curve.G1Affine
	foldhiddeneval.MultiExp(hidden_eval, gammas, ecc.MultiExpConfig{})

	return foldcom, foldhiddeneval

}

// func BatchhiddenVerifySinglePoint(digests []Digest, hiddeneval []curve.G1Affine, 
// foldwit curve.G1Affine, point fr.Element, vk VerifyingKey) {
// 	foldedDigest, foldedHiddenEval:=Foldcom_hiddeneval(point, digests, hiddeneval)

// 	var foldedProof ZeroKnowledgeOpeningProof
// 	foldedProof.H.Set(&foldwit)
// 	foldedProof.CommittedValue.Set(&foldedHiddenEval)

// 	// verify the foldedProof against the foldedDigest
// 	fmt.Println("-----", HiddenVerify(&foldedDigest, &foldedProof, point, vk))

// }

func BatchhiddenVerifySinglePoint(digests []Digest, hiddeneval_wit []curve.G1Affine, 
	point fr.Element, vk VerifyingKey) bool {
		length :=len(hiddeneval_wit)
		foldedDigest, foldedHiddenEval:=Foldcom_hiddeneval(point, digests, hiddeneval_wit[:length-1])
	
		var foldedProof ZeroKnowledgeOpeningProof
		foldedProof.H.Set(&hiddeneval_wit[length-1])
		foldedProof.CommittedValue.Set(&foldedHiddenEval)
	
		// verify the foldedProof against the foldedDigest
		// fmt.Println("-----", HiddenVerify(&foldedDigest, &foldedProof, point, vk))
		return HiddenVerify(&foldedDigest, &foldedProof, point, vk)
	
	}



