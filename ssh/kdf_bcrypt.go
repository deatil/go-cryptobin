package ssh

import (
    "bytes"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/bcrypt_pbkdf"
)

var (
    bcryptName = "bcrypt"
)

// bcrypt 数据
type bcryptParams struct {}

func (this bcryptParams) DeriveKey(password []byte, salt []byte, rounds int, size int) (key []byte, err error) {
    return bcrypt_pbkdf.Key(
        password, salt,
        rounds, size,
    )
}

// BcryptOpts 设置
type BcryptOpts struct {
    SaltSize int
    Rounds   int
}

func (this BcryptOpts) DeriveKey(password []byte, size int) (key []byte, params string, err error) {
    salt, err := genRandom(this.SaltSize)
    if err != nil {
        return nil, "", err
    }

    key, err = bcrypt_pbkdf.Key(
        password, salt,
        this.Rounds, size,
    )
    if err != nil {
        return nil, "", err
    }

    buf := new(bytes.Buffer)
    binary.Write(buf, binary.BigEndian, uint32(this.SaltSize))
    binary.Write(buf, binary.BigEndian, salt)
    binary.Write(buf, binary.BigEndian, uint32(this.Rounds))
    params = buf.String()

    return key, params, nil
}

func (this BcryptOpts) GetSaltSize() int {
    return this.SaltSize
}

func (this BcryptOpts) Name() string {
    return bcryptName
}

func init() {
    AddKDF(bcryptName, func() KDFParameters {
        return new(bcryptParams)
    })
}
