package tool

import (
    "encoding/binary"
)

func LE2BE_16(inp []byte) []byte {
    i := binary.LittleEndian.Uint16(inp[0:])

    var sav [2]byte
    binary.BigEndian.PutUint16(sav[0:], i)

    return sav[:]
}

func BE2LE_16(inp []byte) []byte {
    i := binary.BigEndian.Uint16(inp[0:])

    var sav [2]byte
    binary.LittleEndian.PutUint16(sav[0:], i)

    return sav[:]
}

func LE2BE_32(inp []byte) []byte {
    i := binary.LittleEndian.Uint32(inp[0:])

    var sav [4]byte
    binary.BigEndian.PutUint32(sav[0:], i)

    return sav[:]
}

func BE2LE_32(inp []byte) []byte {
    i := binary.BigEndian.Uint32(inp[0:])

    var sav [4]byte
    binary.LittleEndian.PutUint32(sav[0:], i)

    return sav[:]
}

func LE2BE_64(inp []byte) []byte {
    i := binary.LittleEndian.Uint64(inp[0:])

    var sav [8]byte
    binary.BigEndian.PutUint64(sav[0:], i)

    return sav[:]
}

func BE2LE_64(inp []byte) []byte {
    i := binary.BigEndian.Uint64(inp[0:])

    var sav [8]byte
    binary.LittleEndian.PutUint64(sav[0:], i)

    return sav[:]
}
