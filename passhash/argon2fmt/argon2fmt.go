package argon2fmt

import (
    "io"
    "fmt"
    "errors"
    "runtime"
    "strconv"
    "strings"
    "crypto/subtle"
    "encoding/base64"

    "github.com/deatil/go-cryptobin/kdf/argon2"
)

// 配置
type Opt struct {
    SaltLen int
    Time    uint32
    Memory  uint32
    Threads uint8
    KeyLen  uint32
}

var (
    // 默认类型
    defaultType = "argon2id"

    // 默认配置
    defaultOpt = Opt{
        SaltLen: 32,
        Time:    1,
        Memory:  64 * 1024,
        Threads: uint8(runtime.NumCPU()),
        KeyLen:  32,
    }
)

// 生成密钥
func GenerateSaltedHash(random io.Reader, password string) (string, error) {
    return GenerateSaltedHashWithTypeAndOpt(random, password, defaultType, defaultOpt)
}

// 生成密钥带类型
func GenerateSaltedHashWithType(random io.Reader, password string, typ string) (string, error) {
    return GenerateSaltedHashWithTypeAndOpt(random, password, typ, defaultOpt)
}

// 生成密钥带类型和设置
func GenerateSaltedHashWithTypeAndOpt(random io.Reader, password string, typ string, opt Opt) (string, error) {
    if len(password) == 0 {
        return "", errors.New("go-cryptobin/argon2fmt: Password length cannot be 0")
    }

    saltLen       := opt.SaltLen
    argon2Time    := opt.Time
    argon2Memory  := opt.Memory
    argon2Threads := opt.Threads
    argon2KeyLen  := opt.KeyLen

    salt, err := generateSalt(random, saltLen)
    if err != nil {
        return "", errors.New("go-cryptobin/argon2fmt: Generate Salt fail")
    }

    var unencodedPassword []byte
    switch typ {
        case "argon2id":
            unencodedPassword = argon2.IDKey(
                []byte(password), salt,
                argon2Time, argon2Memory,
                argon2Threads, argon2KeyLen,
            )
        case "argon2i":
            unencodedPassword = argon2.Key(
                []byte(password), salt,
                argon2Time, argon2Memory,
                argon2Threads, argon2KeyLen,
            )
        case "argon2d":
            unencodedPassword = argon2.DKey(
                []byte(password), salt,
                argon2Time, argon2Memory,
                argon2Threads, argon2KeyLen,
            )
        default:
            return "", errors.New("go-cryptobin/argon2fmt: Invalid Hash Type")
    }

    encodedPassword := base64.RawStdEncoding.EncodeToString(unencodedPassword)
    encodedSalt := base64.RawStdEncoding.EncodeToString(salt)

    hash := fmt.Sprintf(
        "$%s$v=19$m=%d,t=%d,p=%d$%s$%s",
        typ,
        argon2Memory, argon2Time, argon2Threads,
        encodedSalt, encodedPassword,
    )

    return hash, nil
}

// 验证密钥
func CompareHashWithPassword(hash, password string) (bool, error) {
    if len(hash) == 0 || len(password) == 0 {
        return false, errors.New("go-cryptobin/argon2fmt: Arguments cannot be zero length")
    }

    hashParts := strings.Split(hash, "$")
    if len(hashParts) != 6 {
        return false, errors.New("go-cryptobin/argon2fmt: Invalid Data Len")
    }

    passwordType := hashParts[1]

    if hashParts[2] != "v=19" {
        return false, errors.New("go-cryptobin/argon2fmt: Invalid Password Hash Prefix")
    }

    params := strings.Split(hashParts[3], ",")
    if len(params) != 3 {
        return false, errors.New("go-cryptobin/argon2fmt: Invalid Password Hash Params")
    }

    time := 0
    memory := 0
    threads := 0

    for _, paramStr := range params {
        param := strings.Split(paramStr, "=")
        if len(param) != 2 {
            return false, errors.New("go-cryptobin/argon2fmt: Invalid Password Hash Params Data")
        }

        key := param[0]
        switch key {
            case "m":
                memory, _ = strconv.Atoi(param[1])
            case "t":
                time, _ = strconv.Atoi(param[1])
            case "p":
                threads, _ = strconv.Atoi(param[1])
        }
    }

    salt, _ := base64.RawStdEncoding.DecodeString(hashParts[4])
    key, _ := base64.RawStdEncoding.DecodeString(hashParts[5])

    keyLen := len(key)

    var calculatedKey []byte
    switch passwordType {
        case "argon2id":
            calculatedKey = argon2.IDKey(
                []byte(password), salt,
                uint32(time), uint32(memory),
                uint8(threads), uint32(keyLen),
            )
        case "argon2i":
            calculatedKey = argon2.Key(
                []byte(password), salt,
                uint32(time), uint32(memory),
                uint8(threads), uint32(keyLen),
            )
        case "argon2d":
            calculatedKey = argon2.DKey(
                []byte(password), salt,
                uint32(time), uint32(memory),
                uint8(threads), uint32(keyLen),
            )
        default:
            return false, errors.New("go-cryptobin/argon2fmt: Invalid Password Hash Type")
    }

    if subtle.ConstantTimeCompare(key, calculatedKey) != 1 {
        return false, errors.New("go-cryptobin/argon2fmt: Password did not match")
    }

    return true, nil
}

func generateSalt(random io.Reader, length int) ([]byte, error) {
    salt := make([]byte, length)
    _, err := io.ReadFull(random, salt)
    if err != nil {
        return nil, err
    }

    return salt, nil
}
