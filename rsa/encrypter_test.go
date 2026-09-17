package rsa_test

import (
	"crypto/rand"
	"testing"

	. "github.com/deatil/go-cryptobin/rsa"
	cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func TestEncryptPrivateKeyWithOptions(t *testing.T) {
	msg := []byte("12345678abcde")

	{
		ciphertext, err := EncryptPrivateKeyWithOptions(rsaPrivateKey, msg, EncrypterOptions{
			Padding: RsaPkcs1Padding,
		})
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}
	
		demsg, err := DecryptPublicKeyWithOptions(&rsaPrivateKey.PublicKey, ciphertext, EncrypterOptions{
			Padding: RsaPkcs1Padding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}
	
		cryptobin_test.Equal(t, string(msg), string(demsg))
	
		// ========
	
		ciphertext2 := "7b1783ab067d84749b14f4da0fe63467a16c087ac1edf552387665e73047ebd1cc881fc064b5b2e427ceebefd50616f9ada687c828416e44bdaf29ed07d62551"
		ct := decodeHex(ciphertext2)
	
		demsg2, err := DecryptPublicKeyWithOptions(&rsaPrivateKey.PublicKey, ct, EncrypterOptions{
			Padding: RsaPkcs1Padding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message check: %s", err)
		}
	
		cryptobin_test.Equal(t, true, len(demsg2) > 0)
		cryptobin_test.Equal(t, "rsa PKCS1-v1_5 encrypt and decrypt", string(demsg2))
	}

	{
		ciphertext, err := EncryptPrivateKeyWithOptions(rsaPrivateKey, msg, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}
	
		demsg, err := DecryptPublicKeyWithOptions(&rsaPrivateKey.PublicKey, ciphertext, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}
	
		cryptobin_test.Equal(t, string(msg), string(demsg))
	
		// ========
	
		ciphertext2 := "aa63536e7b909eb56b374ab0a66bed075469d8fc4865f00c8c98b11750d393898206fcf03bebf38317a59c4825b58ad4c7143626f4e345ef649665a388da0469"
		ct := decodeHex(ciphertext2)
	
		demsg2, err := DecryptPublicKeyWithOptions(&rsaPrivateKey.PublicKey, ct, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message check: %s", err)
		}
	
		cryptobin_test.Equal(t, true, len(demsg2) > 0)
		cryptobin_test.Equal(t, "rsa PKCS1-v1_5 encrypt and decrypt", string(demsg2))
	}

	{
		msg2 := []byte("rsa PKCS1-v1_5 encrypt and decryptrsa PKCS1-v1_5 encrypt and dec")

		ciphertext, err := EncryptPrivateKeyWithOptions(rsaPrivateKey, msg2, EncrypterOptions{
			Padding: RsaNoPadding,
		})
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}
	
		demsg, err := DecryptPublicKeyWithOptions(&rsaPrivateKey.PublicKey, ciphertext, EncrypterOptions{
			Padding: RsaNoPadding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}
	
		cryptobin_test.Equal(t, string(msg2), string(demsg))
	
		// ========
	
		ciphertext2 := "397f0d2b34463c22dee6fb11edcb881d0c0a9d8ba5bb1587cf259ce5d177c7769b5776927be17c687650602a79c0f45317d85010676b90444f27de51b01725a7"
		ct := decodeHex(ciphertext2)
	
		demsg2, err := DecryptPublicKeyWithOptions(&rsaPrivateKey.PublicKey, ct, EncrypterOptions{
			Padding: RsaNoPadding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message check: %s", err)
		}
	
		cryptobin_test.Equal(t, true, len(demsg2) > 0)
		cryptobin_test.Equal(t, string(msg2), string(demsg2))
	}

	{
		msg2 := []byte("rsa PKCS1-v1_5 encrypt and decryptrsa PKCS1-v1_5 encrypt andd")

		ciphertext, err := EncryptPrivateKeyWithOptions(rsaPrivateKey, msg2, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}
	
		demsg, err := DecryptPublicKeyWithOptions(&rsaPrivateKey.PublicKey, ciphertext, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}
	
		cryptobin_test.Equal(t, string(msg2), string(demsg))
	}

	{
		msg2 := []byte("rsa PKCS1-v1_5 encrypt and decryptrsa PKCS1-v1_5 encrypt and d")

		ciphertext, err := EncryptPrivateKeyWithOptions(rsaPrivateKey, msg2, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}
	
		demsg, err := DecryptPublicKeyWithOptions(&rsaPrivateKey.PublicKey, ciphertext, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}
	
		cryptobin_test.Equal(t, string(msg2), string(demsg))
	}

	{
		msg2 := []byte("rsa PKCS1-v1_5 encrypt and decryptrsa PKCS1-v1_5 encrypt and")

		ciphertext, err := EncryptPrivateKeyWithOptions(rsaPrivateKey, msg2, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}
	
		demsg, err := DecryptPublicKeyWithOptions(&rsaPrivateKey.PublicKey, ciphertext, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}
	
		cryptobin_test.Equal(t, string(msg2), string(demsg))
	}
}

func TestEncryptWithOptions(t *testing.T) {
	msg := []byte("12345678abcde")

	{
		ciphertext, err := EncryptWithOptions(rand.Reader, &rsaPrivateKey.PublicKey, msg, EncrypterOptions{
			Padding: RsaPkcs1Padding,
		})
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}

		demsg, err := DecryptWithOptions(rand.Reader, rsaPrivateKey, ciphertext, EncrypterOptions{
			Padding: RsaPkcs1Padding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}

		cryptobin_test.Equal(t, string(msg), string(demsg))

		// ========

		ciphertext2 := "24d17d224f3181383660c4e7d3d4092cc9f7fb015b344aa24afb90e1979fdfc35e7561b1fe217eb18371bf84a8b54e27b043d7b2f69d0418d6621ff0ab10c484"
		ct := decodeHex(ciphertext2)

		demsg2, err := DecryptWithOptions(rand.Reader, rsaPrivateKey, ct, EncrypterOptions{
			Padding: RsaPkcs1Padding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message check: %s", err)
		}

		cryptobin_test.Equal(t, true, len(demsg2) > 0)
		cryptobin_test.Equal(t, "rsa PKCS1-v1_5 encrypt and decrypt", string(demsg2))
	}

	{
		ciphertext, err := EncryptWithOptions(rand.Reader, &rsaPrivateKey.PublicKey, msg, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}

		demsg, err := DecryptWithOptions(rand.Reader, rsaPrivateKey, ciphertext, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}

		cryptobin_test.Equal(t, string(msg), string(demsg))

		// ========

		ciphertext2 := "a8de190dac0aec1c0ad1cdf2eeece64e9e71845475c315d05c06ac6f35a359fa3afcb89175519c450b8e46a9b64ca1f66740e078aa6efc481bbb2eed61dcf5ed"
		ct := decodeHex(ciphertext2)

		demsg2, err := DecryptWithOptions(rand.Reader, rsaPrivateKey, ct, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message check: %s", err)
		}

		cryptobin_test.Equal(t, true, len(demsg2) > 0)
		cryptobin_test.Equal(t, "rsa PKCS1-v1_5 encrypt and decrypt", string(demsg2))
	}

	{
		msg2 := []byte("rsa PKCS1-v1_5 encrypt and decryptrsa PKCS1-v1_5 encrypt and dec")

		ciphertext, err := EncryptWithOptions(rand.Reader, &rsaPrivateKey.PublicKey, msg2, EncrypterOptions{
			Padding: RsaNoPadding,
		})
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}

		demsg, err := DecryptWithOptions(rand.Reader, rsaPrivateKey, ciphertext, EncrypterOptions{
			Padding: RsaNoPadding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}

		cryptobin_test.Equal(t, string(msg2), string(demsg))

		// ========

		ciphertext2 := "2994d74cb93e57f170f964f8401388b42ba904478a2bba2f0839a313f4a067da998003a99a0f8d7957577e86b220aa0536cbb77c0a53b535140e585a6089ca65"
		ct := decodeHex(ciphertext2)

		demsg2, err := DecryptWithOptions(rand.Reader, rsaPrivateKey, ct, EncrypterOptions{
			Padding: RsaNoPadding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message check: %s", err)
		}

		cryptobin_test.Equal(t, true, len(demsg2) > 0)
		cryptobin_test.Equal(t, string(msg2), string(demsg2))
	}

	{
		msg2 := []byte("rsa PKCS1-v1_5 encrypt and decryptrsa PKCS1-v1_5 encrypt andd")

		ciphertext, err := EncryptWithOptions(rand.Reader, &rsaPrivateKey.PublicKey, msg2, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}

		demsg, err := DecryptWithOptions(rand.Reader, rsaPrivateKey, ciphertext, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}

		cryptobin_test.Equal(t, string(msg2), string(demsg))
	}

	{
		msg2 := []byte("rsa PKCS1-v1_5 encrypt and decryptrsa PKCS1-v1_5 encrypt and d")

		ciphertext, err := EncryptWithOptions(rand.Reader, &rsaPrivateKey.PublicKey, msg2, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}

		demsg, err := DecryptWithOptions(rand.Reader, rsaPrivateKey, ciphertext, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}

		cryptobin_test.Equal(t, string(msg2), string(demsg))
	}

	{
		msg2 := []byte("rsa PKCS1-v1_5 encrypt and decryptrsa PKCS1-v1_5 encrypt and")

		ciphertext, err := EncryptWithOptions(rand.Reader, &rsaPrivateKey.PublicKey, msg2, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if err != nil {
			t.Fatalf("Failed to encrypt message: %s", err)
		}

		demsg, err := DecryptWithOptions(rand.Reader, rsaPrivateKey, ciphertext, EncrypterOptions{
			Padding: RsaX931Padding,
		})
		if ; err != nil {
			t.Fatalf("Failed to decrypt message: %s", err)
		}

		cryptobin_test.Equal(t, string(msg2), string(demsg))
	}
}
