package rsa_test

import (
	"crypto/rand"
	"testing"

	. "github.com/deatil/go-cryptobin/rsa"
	cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var rsaX931PrivateKey = parseKey(testingKey(`-----BEGIN RSA TESTING KEY-----
MIICWwIBAAKBgQCXkhwdfZkthwkHIjrS6RQHx5QQz99uV6NbnNds/WyKlUDfVoh6
lVcT85qrqKNLmiC1ThgYkJz4IspZwxiPNbT5fXEJ5VYi30h+61Nu4kgSYPXGbAcV
mF5XcIcaFgCMh8Is2a0mtDBvv+34Wo8fClWwzeRuf1ghjvxw7Ps0WG2HpwIDAQAB
AoGAe2bEpynzxUJUkk9HDyIeYbsWjJ2BbkfBwzutlJm7fhTILU05bnwZ2i+SNMHm
uQ2yJYqASberZMaGcpBJdYcnYFwD7gCuoXxQokoM/AXzCljlcsUTcZLhhz820TQI
/ZIZ5wmojqW/+08h1rGg5zTgWc0k0Vz3HxIpDDIpAneN7VkCQQDGLQVu+GdvkUZ5
Oky81y9BBRDNQ1qRv4rghDnJckYK2nrH8mb81Abc2jl5u3CCu2P5D7gu+cDw8OUZ
hSos236zAkEAw8vdQFCpdr09KdwwwsluNKxAD2rlFlU1bkvZi1qqoiiDn4hSYYJ4
j6VwSDVi6pNJhLo8Li08yRdN12FFgynNPQJAGeJng0cOu5POEKd8vm2cznFK8ISL
n93U1d5vbdBvNZuzzcnribpn6xDV0QCagXjYZf+XnwsgGFhelCbAi3tf4QJAdKib
Ax8MWXsXXkGbq/NofmnDIWyHYm8Sjs0SqT00Pbn18q++peqe+reP1vY4IZvwSezM
vpaliQshjhqe2C+n4QJAOG1YEz/6HO1WENJSrCYm052XY6WUYWovpoQK7H+s7hjs
337p1vYdte9DzX7KlWAVjLvW94SPQ4+rfAiseKG7zQ==
-----END RSA TESTING KEY-----`))

func TestEncryptPrivateKeyWithOptions(t *testing.T) {
	msg := []byte("12345678abcde")

	{
		encrypter := NewEncrypter()
		encrypter.WithPadding(RsaPkcs1Padding)

		ciphertext, err := encrypter.EncryptPrivateKey(rsaPrivateKey, msg)
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}

		demsg, err := encrypter.DecryptPublicKey(&rsaPrivateKey.PublicKey, ciphertext)
		if err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}

		cryptobin_test.Equal(t, string(msg), string(demsg))

		// ========

		ciphertext2 := "7b1783ab067d84749b14f4da0fe63467a16c087ac1edf552387665e73047ebd1cc881fc064b5b2e427ceebefd50616f9ada687c828416e44bdaf29ed07d62551"
		ct := decodeHex(ciphertext2)

		demsg2, err := encrypter.DecryptPublicKey(&rsaPrivateKey.PublicKey, ct)
		if err != nil {
			t.Fatalf("Failed to decrypt message check: %s", err)
		}

		cryptobin_test.Equal(t, true, len(demsg2) > 0)
		cryptobin_test.Equal(t, "rsa PKCS1-v1_5 encrypt and decrypt", string(demsg2))
	}

	{
		encrypter := NewEncrypter()
		encrypter.WithPadding(RsaX931Padding)

		ciphertext, err := encrypter.EncryptPrivateKey(rsaPrivateKey, msg)
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}

		demsg, err := encrypter.DecryptPublicKey(&rsaPrivateKey.PublicKey, ciphertext)
		if err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}

		cryptobin_test.Equal(t, string(msg), string(demsg))

		// ========

		ciphertext2 := "aa63536e7b909eb56b374ab0a66bed075469d8fc4865f00c8c98b11750d393898206fcf03bebf38317a59c4825b58ad4c7143626f4e345ef649665a388da0469"
		ct := decodeHex(ciphertext2)

		demsg2, err := encrypter.DecryptPublicKey(&rsaPrivateKey.PublicKey, ct)
		if err != nil {
			t.Fatalf("Failed to decrypt message check: %s", err)
		}

		cryptobin_test.Equal(t, true, len(demsg2) > 0)
		cryptobin_test.Equal(t, "rsa PKCS1-v1_5 encrypt and decrypt", string(demsg2))
	}

	{
		msg2 := []byte("rsa PKCS1-v1_5 encrypt and decryptrsa PKCS1-v1_5 encrypt and dec")

		encrypter := NewEncrypter()
		encrypter.WithPadding(RsaNoPadding)

		ciphertext, err := encrypter.EncryptPrivateKey(rsaPrivateKey, msg2)
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}

		demsg, err := encrypter.DecryptPublicKey(&rsaPrivateKey.PublicKey, ciphertext)
		if err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}

		cryptobin_test.Equal(t, string(msg2), string(demsg))

		// ========

		ciphertext2 := "397f0d2b34463c22dee6fb11edcb881d0c0a9d8ba5bb1587cf259ce5d177c7769b5776927be17c687650602a79c0f45317d85010676b90444f27de51b01725a7"
		ct := decodeHex(ciphertext2)

		demsg2, err := encrypter.DecryptPublicKey(&rsaPrivateKey.PublicKey, ct)
		if err != nil {
			t.Fatalf("Failed to decrypt message check: %s", err)
		}

		cryptobin_test.Equal(t, true, len(demsg2) > 0)
		cryptobin_test.Equal(t, string(msg2), string(demsg2))
	}

	{
		msg2 := []byte("rsa PKCS1-v1_5 encrypt and decryptrsa PKCS1-v1_5 encrypt andd")

		encrypter := NewEncrypter()
		encrypter.WithPadding(RsaX931Padding)

		ciphertext, err := encrypter.EncryptPrivateKey(rsaPrivateKey, msg2)
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}

		demsg, err := encrypter.DecryptPublicKey(&rsaPrivateKey.PublicKey, ciphertext)
		if err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}

		cryptobin_test.Equal(t, string(msg2), string(demsg))
	}

	{
		msg2 := []byte("rsa PKCS1-v1_5 encrypt and decryptrsa PKCS1-v1_5 encrypt and d")

		encrypter := NewEncrypter()
		encrypter.WithPadding(RsaX931Padding)

		ciphertext, err := encrypter.EncryptPrivateKey(rsaPrivateKey, msg2)
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}

		demsg, err := encrypter.DecryptPublicKey(&rsaPrivateKey.PublicKey, ciphertext)
		if err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}

		cryptobin_test.Equal(t, string(msg2), string(demsg))
	}

	{
		msg2 := []byte("rsa PKCS1-v1_5 encrypt and decryptrsa PKCS1-v1_5 encrypt and")

		encrypter := NewEncrypter()
		encrypter.WithPadding(RsaX931Padding)

		ciphertext, err := encrypter.EncryptPrivateKey(rsaPrivateKey, msg2)
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}

		demsg, err := encrypter.DecryptPublicKey(&rsaPrivateKey.PublicKey, ciphertext)
		if err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}

		cryptobin_test.Equal(t, string(msg2), string(demsg))
	}
}

func TestEncryptWithOptions(t *testing.T) {
	msg := []byte("12345678abcde")

	{
		encrypter := NewEncrypter()
		encrypter.WithPadding(RsaPkcs1Padding)
		encrypter.WithRandom(rand.Reader)

		ciphertext, err := encrypter.Encrypt(&rsaPrivateKey.PublicKey, msg)
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}

		demsg, err := encrypter.Decrypt(rsaPrivateKey, ciphertext)
		if err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}

		cryptobin_test.Equal(t, string(msg), string(demsg))

		// ========

		ciphertext2 := "24d17d224f3181383660c4e7d3d4092cc9f7fb015b344aa24afb90e1979fdfc35e7561b1fe217eb18371bf84a8b54e27b043d7b2f69d0418d6621ff0ab10c484"
		ct := decodeHex(ciphertext2)

		demsg2, err := encrypter.Decrypt(rsaPrivateKey, ct)
		if err != nil {
			t.Fatalf("Failed to decrypt message check: %s", err)
		}

		cryptobin_test.Equal(t, true, len(demsg2) > 0)
		cryptobin_test.Equal(t, "rsa PKCS1-v1_5 encrypt and decrypt", string(demsg2))
	}

	{
		msg2 := []byte("rsa PKCS1-v1_5 encrypt and decryptrsa PKCS1-v1_5 encrypt and dec")

		encrypter := NewEncrypter()
		encrypter.WithPadding(RsaNoPadding)
		encrypter.WithRandom(rand.Reader)

		ciphertext, err := encrypter.Encrypt(&rsaPrivateKey.PublicKey, msg2)
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}

		demsg, err := encrypter.Decrypt(rsaPrivateKey, ciphertext)
		if err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}

		cryptobin_test.Equal(t, string(msg2), string(demsg))

		// ========

		ciphertext2 := "2994d74cb93e57f170f964f8401388b42ba904478a2bba2f0839a313f4a067da998003a99a0f8d7957577e86b220aa0536cbb77c0a53b535140e585a6089ca65"
		ct := decodeHex(ciphertext2)

		demsg2, err := encrypter.Decrypt(rsaPrivateKey, ct)
		if err != nil {
			t.Fatalf("Failed to decrypt message check: %s", err)
		}

		cryptobin_test.Equal(t, true, len(demsg2) > 0)
		cryptobin_test.Equal(t, string(msg2), string(demsg2))
	}

}

func TestDecryptPublicKeyWithOptionsCheck(t *testing.T) {
	ciphertext2 := "2B576194CCA758B99DE32BB18CEACB77D0EB4AA04E7B44153265F6E812A8F63B2F97F1F06121CEECE7B5B45B22869F067F73D7D97504E2F625324E4127350F711864B6A305F08A50F86FFC0DC52A677A0E9742431193E6F9AB33813390EB403ED8768E14EB237CE15921572BE5870E777468D743032E41DE7FC681EDC1D0824B"
	ct := decodeHex(ciphertext2)

	encrypter := NewEncrypter()
	encrypter.WithPadding(RsaX931Padding)

	demsg2, err := encrypter.DecryptPublicKey(&rsaX931PrivateKey.PublicKey, ct)
	if err != nil {
		t.Fatalf("Failed to decrypt message check: %s", err)
	}

	cryptobin_test.Equal(t, true, len(demsg2) > 0)
	cryptobin_test.Equal(t, "Hello RSA X9.31", string(demsg2))
}

