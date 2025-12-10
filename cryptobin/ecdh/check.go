package ecdh

// Check KeyPair
func (this ECDH) CheckKeyPair() bool {
    // from private key
    pubKeyFromPriKey := this.MakePublicKey().
        CreatePublicKey().
        ToKeyString()

    // pubkey data
    pubKeyFromPubKey := this.CreatePublicKey().ToKeyString()

    if pubKeyFromPriKey == "" || pubKeyFromPubKey == "" {
        return false
    }

    if pubKeyFromPriKey == pubKeyFromPubKey {
        return true
    }

    return false
}
