package main

import (
	"C"

	curve "github.com/consensys/gnark-crypto/ecc/secp256k1"

	Ped "github.com/consensys/gnark-crypto/ecc/secp256k1/fr/pedersen"
)
import (
	"encoding/json"
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/tidwall/gjson"
)

//export pySRSGen
func pySRSGen(srsSize int) *C.char {
	SRS_pk := Ped.Setup(uint64(srsSize))
	json_pk, _ := json.Marshal(SRS_pk)

	return C.CString(string(json_pk))
}

//export pyVMmatrixGen
func pyVMmatrixGen(json_publickey *C.char, t int) *C.char {
	var publickey []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_publickey)), &publickey)
	dim_col := 2*t + 1
	dim_row := 3*t + 1
	vm_matrix := make([][]fr.Element, dim_row)
	for i := 0; i < dim_row; i++ {
		vm_matrix[i] = make([]fr.Element, dim_col)
		var temp fr.Element
		temp.SetUint64(publickey[i].X.Uint64())
		for j := 0; j < dim_col; j++ {
			ExponentElement := new(big.Int).SetInt64(int64(j))
			vm_matrix[i][j].Exp(temp, ExponentElement)
		}
	}
	jsonvm_matrix, _ := json.Marshal(vm_matrix)
	return C.CString(string(jsonvm_matrix))
}

//export pyKeyGeneration
func pyKeyGeneration(json_SRS *C.char, n int) *C.char {
	var SRS *Ped.ProvingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS)), &SRS)
	g := SRS.G[0]

	secretkeys := make([]fr.Element, n)
	serialized_secretkeys := make([][]byte, n)
	for i := 0; i < n; i++ {
		secretkeys[i].SetRandom()
		serialized_secretkeys[i], _ = secretkeys[i].MarshalJSON()
	}
	publickeys := curve.BatchScalarMultiplicationG1(&g, secretkeys)

	var secretkeyBigInt big.Int
	secretkeys[0].BigInt(&secretkeyBigInt)

	// secretkeys_test := make([]fr.Element, n)
	// for i := 0; i < n; i++ {
	// 	secretkeys_test[i].UnmarshalJSON(serialized_secretkeys[i])
	// }

	jsonpublickeys, _ := json.Marshal(publickeys)
	jsonsecretkeys, _ := json.Marshal(serialized_secretkeys)
	var jsonpublicsecretkeys = "{\"publickeys\":" + string(jsonpublickeys) + ",\"secretkeys\":" + string(jsonsecretkeys) + "}"
	return C.CString(string(jsonpublicsecretkeys))
}

//export pyPedSampleSecret
func pyPedSampleSecret(batchsize int) *C.char {
	secret := make([]fr.Element, batchsize)
	for i := 0; i < batchsize; i++ {
		secret[i].SetRandom()
	}
	json_secret, _ := json.Marshal(secret)
	//fmt.Println("output", string(outest))
	return C.CString(string(json_secret))
}

func samplepoly(secret []fr.Element, batch_size int, t int) [][]fr.Element {
	polynomialList := make([][]fr.Element, 0)

	for i := 0; i < batch_size; i++ {
		f_poly := make([]fr.Element, t+1)
		for j := 0; j < t+1; j++ {
			if j == 0 {
				f_poly[j].Set(&secret[i])
			} else {
				f_poly[j].SetRandom()
			}
		}
		polynomialList = append(polynomialList, f_poly)
	}
	f_poly := make([]fr.Element, t+1)
	for j := 0; j < t+1; j++ {
		f_poly[j].SetRandom()
	}
	polynomialList = append(polynomialList, f_poly)

	return polynomialList
}

func Batcheval(f [][]fr.Element, n int) [][]fr.Element {
	res := make([][]fr.Element, n)

	var wg sync.WaitGroup

	for j := 0; j < n; j++ {
		wg.Add(1)
		go func(j int) {
			defer wg.Done()
			var point fr.Element
			point.SetInt64(int64(j + 1))
			res[j] = make([]fr.Element, len(f))
			for i := 0; i < len(f); i++ {
				res[j][i] = Ped.Eval(f[i], point)
			}
		}(j)
	}
	wg.Wait()

	// for j := 0; j < n; j++ {
	// 	var point fr.Element
	// 	res[j] = make([]fr.Element, len(f))
	// 	point.SetInt64(int64(j + 1))
	// 	for i := 0; i < len(f); i++ {
	// 		res[j][i] = Ped.Eval(f[i], point)
	// 	}
	// }
	return res
}

//export pyPedCommit
func pyPedCommit(json_SRS *C.char, json_secret *C.char, t int) *C.char {
	var Pk Ped.ProvingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS)), &Pk)

	var secret []fr.Element
	_ = json.Unmarshal([]byte(C.GoString(json_secret)), &secret)
	batchsize := len(secret)

	polynomialList := samplepoly(secret, batchsize, t)

	commitment := Ped.Commit(Pk, polynomialList)
	json_commitment, _ := json.Marshal(commitment)

	n := 3*t + 1
	evaluation := Batcheval(polynomialList, n)
	json_evaluation, _ := json.Marshal(evaluation)

	var jsoncomandproof = "{\"com\":" + string(json_commitment) + ",\"eval\":" + string(json_evaluation) + "}"

	return C.CString(string(jsoncomandproof))
}

//export pyPedVerify
func pyPedVerify(json_SRS *C.char, json_commitment *C.char, json_eval *C.char, my_id int, degree int) bool {
	var Pk Ped.ProvingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS)), &Pk)

	var commitment []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_commitment)), &commitment)

	var eval []fr.Element
	_ = json.Unmarshal([]byte(C.GoString(json_eval)), &eval)

	var point fr.Element
	point.SetUint64(uint64(my_id + 1))

	return Ped.Verify(Pk, commitment, eval, point, uint64(degree))
}

//export pyPedBatchVerify
func pyPedBatchVerify(json_SRS *C.char, json_commitment *C.char, json_eval *C.char, my_id int, degree int) bool {
	var Pk Ped.ProvingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS)), &Pk)

	var commitment []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_commitment)), &commitment)

	var eval []fr.Element
	_ = json.Unmarshal([]byte(C.GoString(json_eval)), &eval)

	var point fr.Element
	point.SetUint64(uint64(my_id + 1))
	for i := 0; i < len(commitment); i++ {
		if !Ped.Verify(Pk, commitment, eval, point, uint64(degree)) {
			fmt.Println("batch verify Verifivcation passed", i)
			return false
		}
	}
	return true
}

//export pyPedKeyEphemeralGen
func pyPedKeyEphemeralGen(json_SRS_pk *C.char, json_publickey *C.char) *C.char {
	var Pk *Ped.ProvingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS_pk)), &Pk)
	g := Pk.G[0]

	var ephemeralsecretkey fr.Element
	ephemeralsecretkey.SetRandom()
	serialized_ephemeralsecretkey, _ := ephemeralsecretkey.MarshalJSON()

	var ephemeralsecretkeyBigInt big.Int
	ephemeralsecretkey.BigInt(&ephemeralsecretkeyBigInt)

	var ephemeralpublickey curve.G1Affine
	ephemeralpublickey.ScalarMultiplication(&g, &ephemeralsecretkeyBigInt)

	jsonephemeralsecretkey, _ := json.Marshal(serialized_ephemeralsecretkey)
	jsonephemeralpublickey, _ := json.Marshal(ephemeralpublickey)

	var jsonephemeralpublicsecretsharedkey = "{\"ephemeralpublickey\":" + string(jsonephemeralpublickey) + ",\"ephemeralsecretkey\":" + string(jsonephemeralsecretkey) + "}"

	return C.CString(string(jsonephemeralpublicsecretsharedkey))
}

//export pyPedSharedKeysGen_sender
func pyPedSharedKeysGen_sender(json_publickey *C.char, json_ephemeralsecretkey *C.char, index int) *C.char {
	var publickey []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_publickey)), &publickey)

	var ephemeralsecretkey fr.Element
	var ephemeralsecretkeybyte []byte
	_ = json.Unmarshal([]byte(C.GoString(json_ephemeralsecretkey)), &ephemeralsecretkeybyte)
	ephemeralsecretkey.UnmarshalJSON(ephemeralsecretkeybyte)

	var ephemeralsecretkeyBigInt big.Int
	ephemeralsecretkey.BigInt(&ephemeralsecretkeyBigInt)

	var sharedkey_sender curve.G1Affine
	sharedkey_sender.ScalarMultiplication(&publickey[index], &ephemeralsecretkeyBigInt)

	jsonsharedkey_sender, _ := json.Marshal(sharedkey_sender)
	return C.CString(string(jsonsharedkey_sender))

}

func parsePublickey(jsonephemeralpublickey []byte) curve.G1Affine {
	var test curve.G1Affine
	var testx = fp.Element{
		gjson.Get(string(jsonephemeralpublickey), "X.0").Uint(),
		gjson.Get(string(jsonephemeralpublickey), "X.1").Uint(),
		gjson.Get(string(jsonephemeralpublickey), "X.2").Uint(),
		gjson.Get(string(jsonephemeralpublickey), "X.3").Uint(),
	}
	var testy = fp.Element{
		gjson.Get(string(jsonephemeralpublickey), "Y.0").Uint(),
		gjson.Get(string(jsonephemeralpublickey), "Y.1").Uint(),
		gjson.Get(string(jsonephemeralpublickey), "Y.2").Uint(),
		gjson.Get(string(jsonephemeralpublickey), "Y.3").Uint(),
	}
	test.X.Set(&testx)
	test.Y.Set(&testy)

	return test
}

//export pyPedSharedKeysGen_recv
func pyPedSharedKeysGen_recv(json_ephemeralpublickey *C.char, json_secretkey *C.char) *C.char {

	var ephemeralpublickey curve.G1Affine = parsePublickey([]byte(C.GoString(json_ephemeralpublickey)))

	var sk fr.Element
	var skbyte []byte
	_ = json.Unmarshal([]byte(C.GoString(json_secretkey)), &skbyte)
	sk.UnmarshalJSON(skbyte)

	var secretkeyBigInt big.Int
	sk.BigInt(&secretkeyBigInt)

	var sharedkey curve.G1Affine
	sharedkey.ScalarMultiplication(&ephemeralpublickey, &secretkeyBigInt)

	jsonsharedkey, _ := json.Marshal(sharedkey)
	return C.CString(string(jsonsharedkey))
}

func transposeG1Affline(matrix [][]curve.G1Affine) [][]curve.G1Affine {
	rows := len(matrix)
	cols := len(matrix[0])

	result := make([][]curve.G1Affine, cols)
	for i := range result {
		result[i] = make([]curve.G1Affine, rows)
	}

	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			result[j][i].Set(&matrix[i][j])
		}
	}

	return result
}

func transposefrElement(matrix [][]fr.Element) [][]fr.Element {
	rows := len(matrix)
	cols := len(matrix[0])

	result := make([][]fr.Element, cols)
	for i := range result {
		result[i] = make([]fr.Element, rows)
	}

	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			result[j][i].Set(&matrix[i][j])
		}
	}

	return result
}

func DotProductfrElement(vector1, vector2 []fr.Element) fr.Element {
	if len(vector1) != len(vector2) {
		pass
	}

	var result fr.Element
	temp := make([]fr.Element, len(vector1))
	result.SetZero()
	for i := 0; i < len(vector1); i++ {
		temp[i].Mul(&vector1[i], &vector2[i])
		result.Add(&result, &temp[i])
	}

	return result
}

// this function is for generating random shares without random extraction by hyper-invertible matrix
//
//export pyPedRandomShareComputeWithoutRanExt
func pyPedRandomShareComputeWithoutRanExt(json_com *C.char, json_sharelist *C.char) *C.char {

	var commitmentList_All [][]curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_com)), &commitmentList_All)
	var sharelist_All [][]fr.Element
	_ = json.Unmarshal([]byte(C.GoString(json_sharelist)), &sharelist_All)

	random_com := make([]curve.G1Affine, len(commitmentList_All[0]))
	// prod
	for j := 0; j < len(commitmentList_All); j++ {
		var prod curve.G1Affine
		for i := 0; i < len(commitmentList_All[0]); i++ {
			if i == 0 {
				prod.Set(&commitmentList_All[i][j])
				continue
			}
			prod.Add(&prod, &commitmentList_All[i][j])
		}
		random_com[j].Set(&prod)
	}

	rows := len(sharelist_All)
	cols := len(sharelist_All[0])

	random_shares := make([]fr.Element, cols)
	for j := 0; j < cols; j++ {
		var sum fr.Element
		for i := 0; i < rows; i++ {
			if i == 0 {
				sum.Set(&sharelist_All[i][j])
				continue
			}
			sum.Add(&sum, &sharelist_All[i][j])
		}
		random_shares[j].Set(&sum)
	}

	jsonshare, _ := json.Marshal(random_shares)
	jsoncommitment, _ := json.Marshal(random_com)

	var jsoncomandsharelist = "{\"commitment\":" + string(jsoncommitment) + ",\"share\":" + string(jsonshare) + "}"

	return C.CString(string(jsoncomandsharelist))

}

//export pyPedParseRandom_Commit
func pyPedParseRandom_Commit(json_SRS_Pk *C.char, json_commitment *C.char, json_share *C.char, t int, my_id int) *C.char {

	var Pk Ped.ProvingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS_Pk)), &Pk)

	var commitment []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_commitment)), &commitment)

	var share []fr.Element
	_ = json.Unmarshal([]byte(C.GoString(json_share)), &share)

	// compute c = a * b, and T_c = g*c h^c_randomness
	half_length := (len(share) - 1) / 2
	secret_c := make([]fr.Element, half_length)

	for j := 0; j < (half_length); j++ {
		secret_c[j].Mul(&share[j], &share[j+half_length])
	}

	polynomialList := samplepoly(secret_c, len(secret_c), t)

	commitment_c := Ped.Commit(Pk, polynomialList)

	n := 3*t + 1
	evaluation_c := Batcheval(polynomialList, n)

	var point fr.Element
	point.SetUint64(uint64(0))
	evaluationatzerorandomness := Ped.Eval(polynomialList[len(secret_c)], point)
	secret_c = append(secret_c, evaluationatzerorandomness)

	proof_c, T_c, c_randomness := Ped.ProofofEqualityofAggDlog(Pk, secret_c)

	json_proof_S, _ := json.Marshal(proof_c.S)
	json_proof_T, _ := json.Marshal(proof_c.T)
	json_proof_U, _ := json.Marshal(proof_c.U)
	json_proof_V, _ := json.Marshal(proof_c.V)

	var json_proof_c = "{\"S\":" + string(json_proof_S) +
		",\"T\":" + string(json_proof_T) +
		",\"V\":" + string(json_proof_V) +
		",\"U\":" + string(json_proof_U) + "}"

	// compute pedersen commit and commitment proofs for all a, b
	proof_ab, T_ab, ab_randomness := Ped.ProofofEqualityofAggDlog(Pk, share)

	json_proof_S, _ = json.Marshal(proof_ab.S)
	json_proof_T, _ = json.Marshal(proof_ab.T)
	json_proof_U, _ = json.Marshal(proof_ab.U)
	json_proof_V, _ = json.Marshal(proof_ab.V)

	var json_proof_ab = "{\"S\":" + string(json_proof_S) +
		",\"T\":" + string(json_proof_T) +
		",\"V\":" + string(json_proof_V) +
		",\"U\":" + string(json_proof_U) + "}"

	// compute prodproof
	prodproofs := make([]Ped.ProdProof, half_length)

	// for j := 0; j < half_length; j++ {
	// 	prodproofs[j] = Ped.Prodproof(Pk, share[j], ab_randomness[j], share[j+half_length],
	// 		ab_randomness[j+half_length], secret_c[j], c_randomness[j],
	// 		T_ab[j], T_ab[j+half_length], T_c[j])
	// }
	var wg sync.WaitGroup

	var mu sync.Mutex
	for j := 0; j < half_length; j++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			prodproof_j := Ped.Prodproof(Pk, share[index], ab_randomness[index], share[index+half_length],
				ab_randomness[index+half_length], secret_c[index], c_randomness[index],
				T_ab[index], T_ab[index+half_length], T_c[index])

			mu.Lock()
			prodproofs[index] = prodproof_j
			mu.Unlock()
		}(j)
	}
	wg.Wait()

	json_commitment_c, _ := json.Marshal(commitment_c)
	json_evaluation_c, _ := json.Marshal(evaluation_c)
	json_prodProof, _ := json.Marshal(prodproofs)
	json_T_ab, _ := json.Marshal(T_ab)
	json_T_c, _ := json.Marshal(T_c)

	var jsoncom_eval_prodproof = "{\"com_c\":" + string(json_commitment_c) +
		",\"eval_c\":" + string(json_evaluation_c) +
		",\"prodproof\":" + string(json_prodProof) +
		",\"T_ab\":" + string(json_T_ab) +
		",\"T_c\":" + string(json_T_c) +
		",\"proof_ab\":" + json_proof_ab +
		",\"proof_c\":" + json_proof_c + "}"

	return C.CString(string(jsoncom_eval_prodproof))
}

//export pyPedprodverify
func pyPedprodverify(json_Pk *C.char, json_commitment_c *C.char,
	json_commitment_ab *C.char, json_T_ab *C.char, json_T_c *C.char,
	json_proofproduct *C.char, json_proof_ab *C.char, json_proof_c *C.char, dealer_id C.int, t C.int) bool {
	result := true

	var Pk Ped.ProvingKey
	_ = json.Unmarshal([]byte(C.GoString(json_Pk)), &Pk)

	var T_ab []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_T_ab)), &T_ab)

	var T_c []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_T_c)), &T_c)

	var proofproduct []Ped.ProdProof
	_ = json.Unmarshal([]byte(C.GoString(json_proofproduct)), &proofproduct)

	// test the correctness of Prodproofs
	if !Ped.BatchProductVerify(Pk.G[0], Pk.H[0], proofproduct, T_ab, T_c) {
		fmt.Printf("Product verifications are failed for dealer %d\n", dealer_id)
		result = false
	}

	// for j := 0; j < half_length; j++ {
	// 	if !Ped.Prodproofverify(Pk.G[0], Pk.H[0],
	// 		proofproduct[j], T_ab[j], T_ab[j+half_length], T_c[j]) {
	// 		fmt.Printf("Product verifications are failed for dealer %d\n", dealer_id)
	// 		result = false
	// 	}
	// }

	// verify T_ab are correct shares of dealer
	var commitment_ab []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_commitment_ab)), &commitment_ab)
	var proof_ab Ped.ProofofAggDlog
	_ = json.Unmarshal([]byte(C.GoString(json_proof_ab)), &proof_ab)
	var point fr.Element
	point.SetUint64(uint64(dealer_id + 1))
	if !Ped.VerifyAggDlog(Pk, proof_ab, commitment_ab, T_ab, point, int(t)) {
		fmt.Printf("[ab] Verification of shares' correctness fails for dealer %d\n", dealer_id)
		result = false
	}

	// verify T_c are correct shares of commitment_c at zero point
	var commitment_c []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_commitment_c)), &commitment_c)

	var proof_c Ped.ProofofAggDlog
	_ = json.Unmarshal([]byte(C.GoString(json_proof_c)), &proof_c)

	point.SetUint64(uint64(0))
	if !Ped.VerifyAggDlog(Pk, proof_c, commitment_c, T_c, point, int(t)) {
		fmt.Printf("[c] Verification of shares' correctness fails for dealer %d\n", dealer_id)
		result = false
	}

	return result
}

func lagrangeCoefficient(xs []fr.Element, x fr.Element) fr.Element {
	var res fr.Element
	for i := 0; i < len(xs); i++ {
		if xs[i] != x {
			res.Sub(&xs[i], &x)
			res.Inverse(&res)
			res.Mul(&xs[i], &res)
		}
	}
	return res
}

//export pyPedTriplesCompute
func pyPedTriplesCompute(json_commonset *C.char, json_shares_ab *C.char, json_c_shares *C.char, json_c_com *C.char) *C.char {
	var commonset []int
	_ = json.Unmarshal([]byte(C.GoString(json_commonset)), &commonset)

	commonsetFrElement := make([]fr.Element, len(commonset))

	for i := 0; i < len(commonset); i++ {
		commonsetFrElement[i].SetInt64(int64(commonset[i] + 1))
	}

	var shares_ab []fr.Element
	_ = json.Unmarshal([]byte(C.GoString(json_shares_ab)), &shares_ab)

	var shares_c_2t [][]fr.Element
	_ = json.Unmarshal([]byte(C.GoString(json_c_shares)), &shares_c_2t)

	batchsize := len(shares_c_2t[0])

	shares_temp := make([][]fr.Element, len(shares_c_2t))

	lagrangecoeff := make([]fr.Element, len(shares_c_2t))
	// for i := 0; i < len(shares_c_2t); i++ {
	// 	var point fr.Element
	// 	point.SetInt64(int64(i + 1))exponentials
	// 	lagrangecoeff[i] = lagrangeCoefficient(commonsetFrElement, point)
	// }

	var wg sync.WaitGroup
	for i := 0; i < len(shares_c_2t); i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			shares_temp[i] = make([]fr.Element, batchsize)
			for j := 0; j < batchsize; j++ {
				shares_temp[i][j].Mul(&lagrangecoeff[i], &shares_c_2t[i][j])
			}
		}(i)
	}
	wg.Wait()

	// for i := 0; i < len(shares_c_2t); i++ {
	// 	shares_temp[i] = make([]fr.Element, batchsize)
	// 	for j := 0; j < batchsize; j++ {
	// 		shares_temp[i][j].Mul(&lagrangecoeff[i], &shares_c_2t[i][j])
	// 	}

	// }

	tran_shares_temp := transposefrElement(shares_temp)

	var triples Ped.Triples
	triples.A = make([]fr.Element, batchsize-1)
	triples.B = make([]fr.Element, batchsize-1)
	triples.C = make([]fr.Element, batchsize)

	for i := 0; i < batchsize-1; i++ {
		triples.A[i].Set(&shares_ab[i])
		triples.B[i].Set(&shares_ab[i+batchsize])
	}

	for i := 0; i < batchsize; i++ {
		for j := 0; j < len(shares_c_2t); j++ {
			triples.C[i].Add(&triples.C[i], &tran_shares_temp[i][j])
		}
	}

	var commitmentList_c [][]curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_c_com)), &commitmentList_c)

	trans_com_c := transposeG1Affline(commitmentList_c)
	triples_c_com := make([]curve.G1Affine, len(trans_com_c))
	for i := 0; i < len(trans_com_c); i++ {
		triples_c_com[i].MultiExp(trans_com_c[i], lagrangecoeff, ecc.MultiExpConfig{})
	}

	json_triples, _ := json.Marshal(triples)
	json_triples_c_com, _ := json.Marshal(triples_c_com)

	var jsoncom_Triples = "{\"Triples\":" + string(json_triples) +
		",\"C_com\":" + string(json_triples_c_com) + "}"

	return C.CString(string(jsoncom_Triples))
}

func main() {
	// t := 31
	// SRS, _ := kzg_ped.NewSRS(ecc.NextPowerOfTwo(uint64(t+1)), new(big.Int).SetInt64(42))
	// fmt.Println("aaaaa", SRS)
	t := 2
	n := 3*t + 1
	batchsize := 3

	SRS_pk := Ped.Setup(uint64(10))
	// fmt.Println("Ped_srs", SRS_pk)

	secret := make([]fr.Element, batchsize)
	for i := 0; i < batchsize; i++ {
		secret[i].SetRandom()
	}
	polynomialList := samplepoly(secret, batchsize, t)
	// fmt.Println("polynomialList", polynomialList)

	commitment := Ped.Commit(SRS_pk, polynomialList)

	// fmt.Println("commitment", commitment)
	// json_commitment, _ := json.Marshal(commitment)
	// test_json_con := C.CString(string(json_commitment))
	// fmt.Println("test_json_con", test_json_con)

	// var test_test []curve.G1Affine
	// _ = json.Unmarshal([]byte(C.GoString(test_json_con)), &test_test)
	// fmt.Println("test_test", test_test)

	evaluation := Batcheval(polynomialList, n)

	proof, T, _ := Ped.ProofofEqualityofAggDlog(SRS_pk, evaluation[0])

	json_proof_S, _ := json.Marshal(proof.S)
	json_proof_T, _ := json.Marshal(proof.T)
	json_proof_U, _ := json.Marshal(proof.U)
	json_proof_V, _ := json.Marshal(proof.V)

	var json_proof = "{\"S\":" + string(json_proof_S) +
		",\"T\":" + string(json_proof_T) +
		",\"V\":" + string(json_proof_V) +
		",\"U\":" + string(json_proof_U) + "}"

	test_json_proof := C.CString(json_proof)
	// fmt.Println("json_proof", json_proof)
	var test_proof Ped.ProofofAggDlog
	// temp := C.GoString(test_json_proof)
	// fmt.Println("temp", temp)

	err := json.Unmarshal([]byte(C.GoString(test_json_proof)), &test_proof)
	fmt.Println("test_proof", test_proof.S)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	var point fr.Element
	point.SetUint64(uint64(1))
	res := Ped.VerifyAggDlog(SRS_pk, test_proof, commitment, T, point, t)
	fmt.Println("res", res)

	// json_eval, _ := json.Marshal(evaluation)
	// test_json_eval := C.CString(string(json_eval))
	// fmt.Println("test_json_eval", test_json_eval)

	// var test_test [][]fr.Element
	// _ = json.Unmarshal([]byte(C.GoString(test_json_eval)), &test_test)
	// fmt.Println("test_test", test_test[0])

	// fmt.Println("evaluation", evaluation[0])

	for i := 0; i < n; i++ {
		var point fr.Element
		point.SetUint64(uint64(i + 1))
		if Ped.Verify(SRS_pk, commitment, evaluation[i], point, uint64(t)) {
			fmt.Println("Verifivcation passed")
		}
	}

}
