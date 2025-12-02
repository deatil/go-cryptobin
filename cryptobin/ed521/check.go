package ed521

// Check KeyPair
func (this ED521) CheckKeyPair() bool {
    pubKeyFromPriKey := this.MakePublicKey().
        CreatePublicKey().
        ToKeyString()

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
