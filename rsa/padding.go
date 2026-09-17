package rsa

import (
	"crypto/subtle"
	"errors"
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
