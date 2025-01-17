/* Code generated by cmd/cgo; DO NOT EDIT. */

/* package command-line-arguments */


#line 1 "cgo-builtin-export-prolog"

#include <stddef.h>

#ifndef GO_CGO_EXPORT_PROLOGUE_H
#define GO_CGO_EXPORT_PROLOGUE_H

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef struct { const char *p; ptrdiff_t n; } _GoString_;
#endif

#endif

/* Start of preamble from import "C" comments.  */




/* End of preamble from import "C" comments.  */


/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef size_t GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
#ifdef _MSC_VER
#include <complex.h>
typedef _Fcomplex GoComplex64;
typedef _Dcomplex GoComplex128;
#else
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;
#endif

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef _GoString_ GoString;
#endif
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif

extern char* pyNewSRS(GoInt srsSize);
extern char* pyKeyGeneration(char* json_SRS, GoInt n);
extern char* pyKeyEphemeralGen(char* json_SRS_pk);
extern char* pySharedKeysGen_sender(char* json_publickey, char* json_ephemeralsecretkey);
extern char* pySharedKeysGen_recv(char* json_ephemeralpublickey, char* json_secretkey);
extern char* pySampleSecret(GoInt batchsize);
extern char* pyCommit(char* json_SRS_Pk, char* json_secret, GoInt t);
extern GoUint8 pyBatchVerify(char* json_SRS_Vk, char* json_commitmentlist, char* json_prooflist, GoInt i);
extern char* VMmatrixGen(GoInt t);
extern char* pyRandomShareCompute(char* json_matrix, char* json_set, char* json_comlist, char* json_prooflist, GoInt t);
extern char* pyParseRandom(char* json_SRS_Pk, char* json_commitmentlist, char* json_prooflist, GoInt t, GoInt my_id);

// pyBatchhiddenverify verifies hidden evaluation for a fixed point.
//
extern GoUint8 pyBatchhiddenverify(char* json_SRS_Vk, char* json_commitmentlist_ab, char* json_zkProof_ab, GoInt dealer_id);

// pyBatchhiddenzeroverify verifies hidden evaluation for zero point.
//
extern GoUint8 pyBatchhiddenzeroverify(char* json_SRS_Vk, char* json_commitment_c, char* json_zkProof_c_zero);

// pyProdverify verifies product proofs.
//
extern GoUint8 pyProdverify(char* json_SRS_Vk, char* json_zkProof_ab, char* json_zkProof_c_zero, char* json_proofproduct);

// pyTriplesCompute reconstructs triples from secret shares using Lagrange interpolation.
//
extern char* pyTriplesCompute(char* json_commonset, char* json_shares_ab, char* json_c_shares, char* json_c_com);

#ifdef __cplusplus
}
#endif