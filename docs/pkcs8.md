### PKCS8 使用文档


#### 包引入 / import pkcs8
~~~go
import (
    "github.com/deatil/go-cryptobin/pkcs8"
)
~~~


#### 加密证书 / Encrypt key

~~~go
import (
    "crypto/rand"

    "github.com/deatil/go-cryptobin/pkcs8"
)

func main() {
    var data []byte = []byte("...")
    var pass []byte = []byte("...")

    var opts = pkcs8.DefaultOpts

    // 可用默认设置: [DefaultPBKDF2Opts | DefaultSMPBKDF2Opts | DefaultScryptOpts | DefaultOpts | DefaultSMOpts]
    block, err := EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", data, pass, opts)

    // 自定义设置
    var opts1 = pkcs8.Opts{
        Cipher:  pkcs8.SM4CFB,
        KDFOpts: pkcs8.SMPBKDF2Opts{
            SaltSize:       8,
            IterationCount: 5000,
            HMACHash:       pkcs8.DefaultSMHash,
        },
    }
    var opts2 = pkcs8.PBKDF2Opts{
        SaltSize:       16,
        IterationCount: 10000,
    }
    var opts3 = pkcs8.SMPBKDF2Opts{
        SaltSize:       16,
        IterationCount: 10000,
        HMACHash:       DefaultSMHash,
    }
    var opts4 = pkcs8.ScryptOpts{
        SaltSize:                 16,
        CostParameter:            1 << 2,
        BlockSize:                8,
        ParallelizationParameter: 1,
    }
    var opts5 = pkcs8.Opts{
        Cipher:  pkcs8.AES256CBC,
        KDFOpts: pkcs8.DefaultPBKDF2Opts,
    }

    // 使用铺助函数生成设置
    opts, err := pkcs8.MakeOpts("AES256CBC", "SHA256")
    opts, err := pkcs8.MakeOpts(pkcs8.AES256CBC, SHA256)
    opts, err := pkcs8.MakeOpts(pkcs8.SHA1AndDES)

}
~~~


#### 解密加密证书 / Decrypt key

~~~go
import (
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs8"
)

func main() {
    var pemkey []byte = []byte("...")
    var password []byte = []byte("...")

    block, _ := pem.Decode(pemkey)

    dekey, err := DecryptPEMBlock(block, password)
    if err != nil {
        // return error
    }
}
