package rsa

import (
	"crypto/subtle"
	"errors"
	"hash"
	"io"
)

func rsaPkcs1Type1Pad(emLen int, msg []byte) ([]byte, error) {
	if len(msg) > emLen-11 {
		return nil, ErrMessageTooLong
	}

	// EM = 0x00 || 0x01 || PS || 0x00 || M
	em := make([]byte, emLen)
	em[1] = 1

	for i := 2; i < emLen-len(msg)-1; i++ {
		em[i] = 0xff
	}

	em[len(em)-len(msg)-1] = 0
	copy(em[len(em)-len(msg):], msg)

	return em, nil
}

func rsaPkcs1Type1Unpad(k int, em []byte) ([]byte, error) {
	if k < 11 {
		return nil, ErrDecryption
	}

	if em[0] != 0 || (em[1] != 0 && em[1] != 1) {
		return nil, errors.New("go-cryptobin/rsa: Invalid header")
	}

	i := 2
	for i < len(em) {
		if em[i] != 0xff {
			if em[i] == 0 {
				break
			}
		}

		i += 1
	}

	i += 1

	if i == len(em) {
		return []byte{}, nil
	}

	if i-1 < 8 {
		return nil, errors.New("go-cryptobin/rsa: Inconsistent")
	}

	return em[i:], nil
}

func rsaPkcs1Type2Pad(random io.Reader, emLen int, msg []byte) ([]byte, error) {
	if len(msg) > emLen-11 {
		return nil, ErrMessageTooLong
	}

	// EM = 0x00 || 0x02 || PS || 0x00 || M
	em := make([]byte, emLen)
	em[1] = 2

	ps, mm := em[2:len(em)-len(msg)-1], em[len(em)-len(msg):]

	err := nonZeroRandomBytes(ps, random)
	if err != nil {
		return nil, err
	}

	em[len(em)-len(msg)-1] = 0
	copy(mm, msg)

	return em, nil
}

func rsaPkcs1Type2Unpad(k int, em []byte) ([]byte, error) {
	if k < 11 {
		return nil, ErrDecryption
	}

	valid, out, index, err := rsaPkcs1Type2UnpadInternal(em)
	if err != nil {
		return nil, err
	}
	if valid == 0 {
		return nil, ErrDecryption
	}

	return out[index:], nil
}

func rsaPkcs1Type2UnpadInternal(em []byte) (valid int, newEm []byte, index int, err error) {
	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)
	secondByteIsTwo := subtle.ConstantTimeByteEq(em[1], 2)

	// The remainder of the plaintext must be a string of non-zero random
	// octets, followed by a 0, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the zero.
	//   index: the offset of the first zero byte.
	lookingForIndex := 1

	for i := 2; i < len(em); i++ {
		equals0 := subtle.ConstantTimeByteEq(em[i], 0)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals0, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals0, 0, lookingForIndex)
	}

	// The PS padding must be at least 8 bytes long, and it starts two
	// bytes into em.
	validPS := subtle.ConstantTimeLessOrEq(2+8, index)

	valid = firstByteIsZero & secondByteIsTwo & (^lookingForIndex & 1) & validPS
	index = subtle.ConstantTimeSelect(valid, index+1, 0)
	return valid, em, index, nil
}

func rsaOaepPad(hash, mgfHash hash.Hash, random io.Reader, emLen int, msg []byte, label []byte) ([]byte, error) {
	if len(msg) > emLen-2*hash.Size()-2 {
		return nil, ErrMessageTooLong
	}

	hash.Reset()
	hash.Write(label)
	lHash := hash.Sum(nil)

	em := make([]byte, emLen)
	seed := em[1 : 1+hash.Size()]
	db := em[1+hash.Size():]

	copy(db[0:hash.Size()], lHash)
	db[len(db)-len(msg)-1] = 1
	copy(db[len(db)-len(msg):], msg)

	_, err := io.ReadFull(random, seed)
	if err != nil {
		return nil, err
	}

	mgf1XOR(db, mgfHash, seed)
	mgf1XOR(seed, mgfHash, db)

	return em, nil
}

func rsaOaepUnpad(hash, mgfHash hash.Hash, k int, em []byte, label []byte) ([]byte, error) {
	if len(em) > k || k < hash.Size()*2+2 {
		return nil, ErrDecryption
	}

	hash.Reset()
	hash.Write(label)
	lHash := hash.Sum(nil)

	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)

	seed := em[1 : hash.Size()+1]
	db := em[hash.Size()+1:]

	mgf1XOR(seed, mgfHash, db)
	mgf1XOR(db, mgfHash, seed)

	lHash2 := db[0:hash.Size()]

	// We have to validate the plaintext in constant time in order to avoid
	// attacks like: J. Manger. A Chosen Ciphertext Attack on RSA Optimal
	// Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1
	// v2.0. In J. Kilian, editor, Advances in Cryptology.
	lHash2Good := subtle.ConstantTimeCompare(lHash, lHash2)

	// The remainder of the plaintext must be zero or more 0x00, followed
	// by 0x01, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the 0x01
	//   index: the offset of the first 0x01 byte
	//   invalid: 1 iff we saw a non-zero byte before the 0x01.
	var lookingForIndex, index, invalid int
	lookingForIndex = 1
	rest := db[hash.Size():]

	for i := 0; i < len(rest); i++ {
		equals0 := subtle.ConstantTimeByteEq(rest[i], 0)
		equals1 := subtle.ConstantTimeByteEq(rest[i], 1)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals1, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals1, 0, lookingForIndex)
		invalid = subtle.ConstantTimeSelect(lookingForIndex&^equals0, 1, invalid)
	}

	if firstByteIsZero&lHash2Good&^invalid&^lookingForIndex != 1 {
		return nil, ErrDecryption
	}

	return rest[index+1:], nil
}

func rsaX931Pad(emLen int, msg []byte) ([]byte, error) {
	em := make([]byte, emLen)

	j := emLen - len(msg) - 2
	if j < 0 {
		return nil, errors.New("go-cryptobin/rsa: Msg too large")
	}

	if j == 0 {
		em[0] = 0x6a
	} else {
		em[0] = 0x6b
		if j > 1 {
			for i := 1; i < j; i++ {
				em[i] = 0xbb
			}
		}
		em[j] = 0xba
	}

	copy(em[len(em)-len(msg)-1:], msg)
	em[len(em)-1] = 0xcc

	return em, nil
}

func rsaX931Unpad(k int, em []byte) ([]byte, error) {
	if k < 2 {
		return nil, ErrDecryption
	}

	i := 0
	j := 0

	if em[0] != 0x6a && em[0] != 0x6b {
		return nil, errors.New("go-cryptobin/rsa: Invalid Header")
	}

	if em[0] == 0x6b {
		j = len(em) - 3

		i = 0
		for ; i < j; i += 1 {
			if em[i+1] == 0xba {
				break
			}

			if em[i+1] != 0xbb {
				return nil, errors.New("go-cryptobin/rsa: Invalid Padding")
			}
		}

		j -= i
	} else {
		j = len(em) - 2
	}

	if em[len(em)-1] != 0xcc {
		return nil, errors.New("go-cryptobin/rsa: Invalid Trailer")
	}

	return em[len(em)-j-1 : len(em)-1], nil
}

func rsaNoPad(emLen int, msg []byte) ([]byte, error) {
	if len(msg) > emLen {
		return nil, errors.New("go-cryptobin/rsa: Msg Too Large For Key Size")
	}
	if len(msg) < emLen {
		return nil, errors.New("go-cryptobin/rsa: Msg Too Small For Key Size")
	}

	return msg, nil
}

func rsaNoUnpad(k int, em []byte) ([]byte, error) {
	if k != len(em) {
		return nil, ErrDecryption
	}

	return em, nil
}
