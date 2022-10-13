package jceks

import (
    "io"
    "fmt"
    "time"
    "bytes"
    "errors"
    "crypto"
    "crypto/sha1"
    "crypto/x509"
    "crypto/hmac"
    "crypto/subtle"
)

func (this *BKS) readBksCert(r io.Reader) (*bksTrustedCertEntry, error) {
    certType, err := readUTF(r)
    if err != nil {
        return nil, err
    }

    certData, err := readBytes(r)
    if err != nil {
        return nil, err
    }

    entry := &bksTrustedCertEntry{}
    entry.cert = certData
    entry.certType = certType

    return entry, nil
}

func (this *BKS) readBksKey(r io.Reader) (*bksKeyEntry, error) {
    keyType, err := readUint8(r)
    if err != nil {
        return nil, err
    }

    keyFormat, err := readUTF(r)
    if err != nil {
        return nil, err
    }

    keyAlgorithm, err := readUTF(r)
    if err != nil {
        return nil, err
    }

    keyEnc, err := readBytes(r)
    if err != nil {
        return nil, err
    }

    entry := &bksKeyEntry{}
    entry.keyType = int(keyType)
    entry.format = keyFormat
    entry.algorithm = keyAlgorithm
    entry.encoded = keyEnc

    return entry, nil
}

func (this *BKS) readBksSecret(r io.Reader) (*bksSecretKeyEntry, error) {
    secretData, err := readBytes(r)
    if err != nil {
        return nil, err
    }

    entry := &bksSecretKeyEntry{}
    entry.secret = secretData

    return entry, nil
}

// 解密
func (this *BKS) readBksSealed(r io.Reader) (*bksSealedKeyEntry, error) {
    sealedData, err := readBytes(r)
    if err != nil {
        return nil, err
    }

    entry := &bksSealedKeyEntry{}
    entry.encrypted = sealedData

    return entry, nil
}

// 解析
func (this *BKS) loadBksEntries(r io.Reader, password string, tryDecryptKeys bool) error {
    for {
        tag, err := readUint8(r)
        if err != nil {
            return err
        }

        if int(tag) == 0 {
            break
        }

        alias, err := readUTF(r)
        if err != nil {
            return err
        }

        date, err := readDate(r)
        if err != nil {
            return err
        }

        chainLength, err := readInt32(r)
        if err != nil {
            return err
        }

        certChain := make([][]byte, 0)
        for i := 0; i < int(chainLength); i++ {
            entry, err := this.readBksCert(r)
            if err != nil {
                return err
            }

            certChain = append(certChain, entry.cert)
        }

        var entry BksEntry
        switch int(tag) {
            case 1:
                entry, err = this.readBksCert(r)
            case 2:
                entry, err = this.readBksKey(r)
            case 3:
                entry, err = this.readBksSecret(r)
            case 4:
                entry, err = this.readBksSealed(r)
            default:
                return fmt.Errorf("Unsupported BKS keystore type: %d", tag)
        }

        if err != nil {
            return fmt.Errorf("BKS keystore type: %d, err: %s", tag, err.Error())
        }

        entry.WithData(alias, date, certChain)

        if tryDecryptKeys {
            entry.Decrypt(password)
        }

        if isInArray[any](alias, this.entries) {
            return fmt.Errorf("Found duplicate alias '%s'", alias)
        }

        this.entries[alias] = entry
    }

    return nil
}

// 解析
func (this *BKS) Parse(r io.Reader, password string, tryDecryptKey ...bool) error {
    tryDecryptKeys := true
    if len(tryDecryptKey) > 0 {
        tryDecryptKeys = tryDecryptKey[0]
    }

    version, err := readUint32(r)
    if err != nil {
        return err
    }

    if version != BksVersionV1 && version != BksVersionV2 {
        return fmt.Errorf("Unsupported BKS keystore version; only V1 and V2 supported, found v%d", version)
    }

    this.version = version
    this.storeType = "bks"

    salt, err := readBytes(r)
    if err != nil {
        return err
    }

    iterationCount, err := readInt32(r)
    if err != nil {
        return err
    }

    hmacFn := sha1.New
    hmacDigestSize := hmacFn().Size()
    hmacKeySize := hmacDigestSize*8
    if version == 1 {
        hmacKeySize = hmacDigestSize
    }

    hmacKey := derivedHmacKey(password, string(salt), int(iterationCount), hmacKeySize/8, hmacFn)
    hmac := hmac.New(sha1.New, hmacKey)

    r = io.TeeReader(r, hmac)

    err = this.loadBksEntries(r, password, tryDecryptKeys)
    if err != nil {
        return err
    }

    computed := hmac.Sum([]byte{})
    computedLen := len(computed)

    actual, err := readOnly(r, int32(computedLen))
    if err != nil {
        return err
    }

    if subtle.ConstantTimeCompare(computed, actual) != 1 {
        return fmt.Errorf("keystore was tampered with or password was incorrect")
    }

    return nil
}

// 解析
func (this *BKS) Decrypt(alias string, password string) error {
    entry, ok := this.entries[alias]
    if !ok {
        return errors.New("no data")
    }

    switch t := entry.(type) {
        case BksEntry:
            return t.Decrypt(password)
    }

    return nil
}

// GetKeyTypeString
func (this *BKS) GetKeyType(alias string) (keyType string, err error) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *bksKeyEntry:
            keyType = t.TypeString()
    }

    return
}

// GetKeys
func (this *BKS) GetKey(alias string) (
    privateKey crypto.PrivateKey,
    publicKey crypto.PublicKey,
    secret []byte,
    err error,
) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *bksKeyEntry:
            privateKey, publicKey, secret, err = t.Recover()
            if err != nil {
                return
            }
    }

    return
}

// GetCertTypeString
func (this *BKS) GetCertType(alias string) (certType string, err error) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *bksTrustedCertEntry:
            certType = t.certType
    }

    return
}

// GetCert
func (this *BKS) GetCert(alias string) (
    cert *x509.Certificate,
    err error,
) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *bksTrustedCertEntry:
            cert, err = x509.ParseCertificate(t.cert)
            if err != nil {
                return
            }
    }

    return
}

// GetSecretKey
func (this *BKS) GetSecretKey(alias string) (
    secret []byte,
    err error,
) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *bksSecretKeyEntry:
            secret = t.secret
    }

    return
}

// GetSealedKeyType
func (this *BKS) GetSealedKeyType(alias string) (keyType string, err error) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *bksSealedKeyEntry:
            keyType = t.nested.TypeString()
    }

    return
}

// GetSecretKey
func (this *BKS) GetSealedKey(alias string) (
    privateKey crypto.PrivateKey,
    publicKey crypto.PublicKey,
    secret []byte,
    err error,
) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case *bksSealedKeyEntry:
            privateKey, publicKey, secret, err = t.nested.Recover()
            if err != nil {
                return
            }
    }

    return
}

// GetCertChain
func (this *BKS) GetCertChain(alias string) (certChain []*x509.Certificate, err error) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case BksDataEntry:
            certChain, err = parseCertChain(t.GetCertChain())
    }

    return
}

// GetCreateDate
func (this *BKS) GetCreateDate(alias string) (date time.Time, err error) {
    entry, ok := this.entries[alias]
    if !ok {
        err = errors.New("no data")
        return
    }

    switch t := entry.(type) {
        case BksDataEntry:
            date = t.GetDate()
    }

    return
}

// ListCerts
func (this *BKS) ListCerts() []string {
    var r []string

    for k, v := range this.entries {
        if _, ok := v.(*bksTrustedCertEntry); ok {
            r = append(r, k)
        }
    }

    return r
}

// ListSecretKeys lists the names of the SecretKey stored in the key store.
func (this *BKS) ListSecretKeys() []string {
    var r []string

    for k, v := range this.entries {
        if _, ok := v.(*bksSecretKeyEntry); ok {
            r = append(r, k)
        }
    }

    return r
}

// ListSealedKeys
func (this *BKS) ListSealedKeys() []string {
    var r []string
    for k, v := range this.entries {
        if _, ok := v.(*bksSealedKeyEntry); ok {
            r = append(r, k)
        }
    }

    return r
}

// ListKeys
func (this *BKS) ListKeys() []string {
    var r []string
    for k, v := range this.entries {
        if _, ok := v.(*bksKeyEntry); ok {
            r = append(r, k)
        }
    }

    return r
}

func (this *BKS) Version() uint32 {
    return this.version
}

func (this *BKS) StoreType() string {
    return this.storeType
}

func (this *BKS) String() string {
    var buf bytes.Buffer

    for k, v := range this.entries {
        fmt.Fprintf(&buf, "%s\n", k)
        fmt.Fprintf(&buf, "  %s\n", v)
    }

    return buf.String()
}
