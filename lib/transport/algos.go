package transport

import "github.com/flynn/noise"

var NOISE_DH noise.DHFunc = noise.DH25519
var NOISE_CIPHER noise.CipherFunc = noise.CipherChaChaPoly
var NOISE_HASH noise.HashFunc = noise.HashSHA256

var NOISE_CIPHERSUITE noise.CipherSuite = noise.NewCipherSuite(
	NOISE_DH,
	NOISE_CIPHER,
	NOISE_HASH,
)

