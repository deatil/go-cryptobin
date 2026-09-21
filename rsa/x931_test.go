package rsa_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	. "github.com/deatil/go-cryptobin/rsa"
)

type signX931Test struct {
	in, out string
}

var signX931Tests = []signX931Test{
	{"Test.\n", "34c63d9486d82d851b83f673994b51f7a59ae368653faa5b994c901948331ac3230b56f199e1046744c976ec7985b0581a96fa8deda775398223661a37f3c7af"},
}

func TestSignX931(t *testing.T) {
	for i, test := range signX931Tests {
		h := sha256.New()
		h.Write([]byte(test.in))
		digest := h.Sum(nil)

		s, err := SignX931(rsaPrivateKey, X931HasherSha256, digest)
		if err != nil {
			t.Errorf("#%d %s", i, err)
		}

		expected, _ := hex.DecodeString(test.out)
		if !bytes.Equal(s, expected) {
			t.Errorf("#%d got: %x want: %x", i, s, expected)
		}
	}
}

func TestVerifyX931(t *testing.T) {
	for i, test := range signX931Tests {
		h := sha256.New()
		h.Write([]byte(test.in))
		digest := h.Sum(nil)

		sig, _ := hex.DecodeString(test.out)

		err := VerifyX931(&rsaPrivateKey.PublicKey, X931HasherSha256, digest, sig)
		if err != nil {
			t.Errorf("#%d %s", i, err)
		}
	}
}

func getX931PrivateKey() *PrivateKey {
	prikey_pem := `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCqNAuNDNT4nYxe
JuL34+QCGn3yiJsefRWKHbX07+vcGWrbT3U2gmG2iyXdgcyMfGg5Qmy473d04Qqy
94vwYHJdq6EALpNoZhSXQoEl6JGGYnGgMN/paO31o6T+TbPHaYak+PFNjnwYUQOu
4sdWI4eJRjz12JoA4Upr3uQs4rN18xgU0IR0RgCG0i2cIwnjmYEyBQA+79C6Z3EZ
8z7CpnTgt4HnkYaFGISXghJSYWyiK1Lw8CtqCrgkfyL5uO1pISi/QV0laZb2qW2x
HubMuHBprqzRN/66JZZMDAEeoLl3Wb0asB9oR5ghKZ+cfDUxonKRR6vMGkBJxg5j
CVwi+DR9AgMBAAECggEAH7qYjaie+iLapEGhDZ+q5XZ9VK2BJ1efoJIF1d21DSCi
4jPnkKwRHafGfQrhsC3P+x6mKHqhvQTnyvGpYXwFTe99Eczc93kSLRl9fGzk1hW7
g2ahE0DXnXNugmbHVS0Xp+DtkOz3NsxBgMRvbyAr99wDaLxCh1f4WPAh/rkbRekn
X70KzpfKh5JO2pg1ouYofZO6BF8BdXsxNvJkuI3LePdoJ7umK2/3RtsC6elek93q
l7u0paZXtHiABjfbOPn6WzDdxYcaFfa9KQYviRPlj860JxO6WWRhjx6Y2hPjzHwq
oLt3IhCFoPvNOr0wOrii3rIjkfZ+FIwjVxAsAhjq8QKBgQDo/w7l95TRJLjP/I2w
SWH7+E6ackQPKUV0TZGbDoZG86aGKywgMjmAqdR8ZnRuprbmDE84DWiLwvmQayUf
Uf73k1AUXrbOgyCblCMoSEXV+Hf1RbgzgGk6wQXP0ZiyVb7uaGtuaV/Oh/qrJYau
DKT18lX+4z67v9UHMT57ZPzikQKBgQC7Aed4tEfuQYDajusdc6UYqG8a4blVJrxb
SZREGNHY/nyjGQBFyR3qKfzxdJY/hB87icATNa4leFTD+kHS5x5ZvCoB6tIIkwgu
gm9vY77DSamr3Mg9EORCnkhpue9B8kvt1LLxjecQ1ifc3/jAEAil62D02QPVEGtp
hE8bQszRLQKBgDETaCPwHhxfS74jSATVsBnOl1/YqZU38DUrEXxDdu0C7RRdi5HM
gmgjXWpGekfEPcn+1cDMsjSeAMr2hn8uWjHziW6A9KhS3k9myHD3qB4Fk97JrJ7M
cV26wmqfjzYg8XJt9BLxhwiNg7MA2HlYmHZlcM+bNd997HTzXmHHR6zBAoGAV/a2
VZ2fdB/Vp3iweWMLVoTr9h4VGkulL991YW63TrWuFN3OtgS7EIl9lGn9vpS8SDos
YhzO9IscfC68RaM3MIiEzfARqbzXjWEHX8LwWVXN/KxWd/r5E6j2cNzoAQIi2xVA
ssTH2rCRgaDMljM0ji8gpStrVQ5rJ+/3ceBDDWUCgYAjB8wFW0Ci+VExf9UyCPiH
J8nmu//Uls7wBmK80C6vzh4mGHuBo6UV38k0evhkxUKLp+hJyoed0KQ3oMQ1T4kt
7V9Q9dOkDoG8UzQexcfho71K/9DShCVTZDie7m5r50f/KedMYQuCvIjA9yk5pcYY
53yKpPWjiBlznEAfI7ihrA==
-----END PRIVATE KEY-----`

	der := fromPem(prikey_pem)

	prikey, _ := ParsePKCS8PrivateKey(der)

	return prikey
}

func TestVerifyX931_Check(t *testing.T) {
	prikey := getX931PrivateKey()

	msg := []byte("This is a message signed with RSA X9.31 + SHA-256.")

	h := sha256.New()
	h.Write(msg)
	digest := h.Sum(nil)

	siged := "4CF5776AA00705940A42EE50707C2EA5978ED289D449E1F28F937EC8A5EDE3D8F8F2EB9C0E5EC87E3EA23D1DCB4F87C0843766D6C1A53391676014B857E9DB09EC57D4C8A5ACFB81D33336F56F0032D6ADE46C567296B6ADB59E14AEBFD2D20C4D1D2604966063F61364546F68CE49E3AE71B027FA52CBDF7386C5C96F4F59B2E3D2D2B9F900EE5FD35FA127E7574A3055779D9C9178E327E0240A0FC530D6C877B87A101795F57168D1110CB97CE52F03113DBF0FC4B2F3FA3ECC10CA322A7FCBB3D70CDFF5F8B5DEC7B1860DC862A9F361AF56C3AE5B3074CDED0EB42323AFAC96647ECCFDAB5F4091257D089C776C60C367ACB1CC4BDBA899E24EBDDF6A67"
	sig, _ := hex.DecodeString(siged)

	err := VerifyX931(&prikey.PublicKey, X931HasherSha256, digest, sig)
	if err != nil {
		t.Errorf("%s", err)
	}
}

func TestGenerateX931Key_Check(t *testing.T) {
	prikey, err := GenerateX931Key(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("genkey test\n")

	h := sha256.New()
	h.Write(msg)
	digest := h.Sum(nil)

	sig, err := SignX931(prikey, X931HasherSha256, digest)
	if err != nil {
		t.Fatalf("SignX931 failed: %s", err)
	}

	if err := VerifyX931(&prikey.PublicKey, X931HasherSha256, digest, sig); err != nil {
		t.Fatalf("signature failed to verify: %s", err)
	}
}
