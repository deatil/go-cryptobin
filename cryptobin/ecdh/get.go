package ecdh

import (
    "crypto/ecdh"
)

// Get PrivateKey
func (this ECDH) GetPrivateKey() *ecdh.PrivateKey {
    return this.privateKey
}

// Get PublicKey
func (this ECDH) GetPublicKey() *ecdh.PublicKey {
    return this.publicKey
}

// Get curve
func (this ECDH) GetCurve() ecdh.Curve {
    return this.curve
}

// Get keyData
func (this ECDH) GetKeyData() []byte {
    return this.keyData
}

// Get secretData
func (this ECDH) GetSecretData() []byte {
    return this.secretData
}

// get errors
func (this ECDH) GetErrors() []error {
    return this.Errors
}
