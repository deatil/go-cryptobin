package bytes

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
)

func Test_BytesSplit(t *testing.T) {
    assertEqual := test.AssertEqualT(t)

    data := BytesSplit([]byte("1234567ytghyuj"), 5)
    check := [][]byte{
        []byte("12345"),
        []byte("67ytg"),
        []byte("hyuj"),
    }

    assertEqual(data, check, "Test_BytesSplit")
}

func Test_StringToBytes(t *testing.T) {
    assertEqual := test.AssertEqualT(t)

    data := StringToBytes("1234567ytghyuj")
    check := []byte("1234567ytghyuj")

    assertEqual(data, check, "Test_StringToBytes")
}

func Test_BytesToString(t *testing.T) {
    assertEqual := test.AssertEqualT(t)

    data := BytesToString([]byte("1234567ytghyuj"))
    check := "1234567ytghyuj"

    assertEqual(data, check, "Test_BytesToString")
}
