package ssh

import (
    "fmt"
    "bytes"
    "encoding/binary"

    "github.com/pkg/errors"
)

func ParseKdfOpts(kdfOpts string) ([]byte, uint32, error) {
    // Read kdf options.
    buf := bytes.NewReader([]byte(kdfOpts))

    var saltLength uint32
    if err := binary.Read(buf, binary.BigEndian, &saltLength); err != nil {
        return nil, 0, errors.New("cannot decode encrypted private keys: bad format")
    }

    salt := make([]byte, saltLength)
    if err := binary.Read(buf, binary.BigEndian, &salt); err != nil {
        return nil, 0, errors.New("cannot decode encrypted private keys: bad format")
    }

    var rounds uint32
    if err := binary.Read(buf, binary.BigEndian, &rounds); err != nil {
        return nil, 0, errors.New("cannot decode encrypted private keys: bad format")
    }

    return salt, rounds, nil
}

func ParseCipher(cipherName string) (Cipher, error) {
    cipher, ok := ciphers[cipherName]
    if !ok {
        return nil, fmt.Errorf("ssh: unsupported cipher (%s)", cipherName)
    }

    newCipher := cipher()

    return newCipher, nil
}

func ParsePbkdf(kdfName string) (KDFParameters, error) {
    kdf, ok := kdfs[kdfName]
    if !ok {
        return nil, fmt.Errorf("ssh: unsupported kdf (%s)", kdfName)
    }

    newKdf := kdf()

    return newKdf, nil
}

func ParseKeytype(keytype string) (Key, error) {
    keyType, ok := keys[keytype]
    if !ok {
        return nil, fmt.Errorf("ssh: unsupported key type %s", keytype)
    }

    newKeytype := keyType()

    return newKeytype, nil
}
