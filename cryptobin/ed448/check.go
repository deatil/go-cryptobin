package ed448

// Check KeyPair
func (this ED448) CheckKeyPair() bool {
    // from private key
    pubKeyFromPriKey := this.MakePublicKey().
        CreatePublicKey().
        ToKeyString()

    // pubkey data
    pubKeyFromPubKey := this.
        CreatePublicKey().
        ToKeyString()

    if pubKeyFromPriKey == "" || pubKeyFromPubKey == "" {
        return false
    }

    if pubKeyFromPriKey == pubKeyFromPubKey {
        return true
    }

    return false
}
