package argon2fmt

import (
    "strconv"
    "strings"
    "testing"
    "crypto/rand"
    "encoding/hex"
)

func fromBin(s string) []byte {
    var bytes []byte

    for i := 0; i < len(s); i += 3 {
        if i + 2 > len(s) {
            return nil
        }

        on, err := strconv.ParseUint(s[i:i+3], 8, 8)
        if err != nil {
            return nil
        }

        bytes = append(bytes, byte(on))
    }

    return bytes
}

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func Test_GenerateSaltedHash(t *testing.T) {
    tests := []struct {
        name         string
        password     string
        hashSegments int
        hashLength   int
        wantErr      bool
    }{
        {"Should Work", "Password1", 6, 118, false},
        {"Should Not Work", "", 1, 0, true},
        {"Should Work 2", "gS</5Tu>3@(<FCtY", 6, 118, false},
        {"Should Work 3", `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, 6, 118, false},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := GenerateSaltedHash(rand.Reader, tt.password)
            hashSegments := strings.Split(got, "$")
            if (err != nil) != tt.wantErr {
                t.Errorf("GenerateSaltedHash() = %v, want %v", err, tt.wantErr)
                return
            }
            if len(hashSegments) != tt.hashSegments {
                t.Errorf("GenerateSaltedHash() had %d segments. Want %d", len(hashSegments), tt.hashSegments)
            }
            if len(got) != tt.hashLength {
                t.Errorf("GenerateSaltedHash() hash length = %v, want %v", len(got), tt.hashLength)
            }
        })
    }
}

func Test_CompareHashWithPassword(t *testing.T) {
    tests := []struct {
        name     string
        hash     string
        password string
        isValid  bool
        wantErr  bool
    }{
        {"Should Work 1", `$argon2i$v=19$m=8,t=1,p=1$YWFhYWFhYWE$3ney028aI7naIJ/5U///1ICfSVF0Ta4jh2SpJ1jhsCE`, `pass`, true, false},
        {"Should Not Work 1", `$v=19$m=8,t=1,p=1$YWFhYWFhYWE$0WM+IC/fpCF2boiNXmu0lnBXDAKes/BHiYuq9abKsWQ`, `pass`, false, true},
        {"Should Not Work 2", ``, ``, false, true},
        {"Should Not Work 3", `badHash`, ``, false, true},
        {"Should Work 2", `$argon2id$v=19$m=8,t=1,p=1$YWFhYWFhYWE$tPAla38/iYe0rtvQKVaPv04WYar67QEGlc4fhxU185s`, `pass`, true, false},
        {"Should Not Work 4", `$argon2id$v=19$m=8,t=1,p=1$hjFhYWFhYWE$tPAla38/iYe0rtvQKVaPv04WYar67QEGlc4fhxU185s`, `pass`, false, true},
        {"Should Not Work 5", `$argon2id$m=8,t=1,p=1$YWFhYWFhYWE$tPAla38/iYe0rtvQKVaPv04WYar67QEGlc4fhxU185s`, `pass`, false, true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := CompareHashWithPassword(tt.hash, tt.password)
            if (err != nil) != tt.wantErr {
                t.Errorf("CompareHashWithPassword() error = %v, wantErr %v", err, tt.wantErr)
                t.Errorf("hash is %v", got)
                return
            }

            if got != tt.isValid {
                t.Errorf("CompareHashWithPassword() = %v, want %v", got, tt.isValid)
            }
        })
    }
}

func Test_GenerateSaltedHashWithType(t *testing.T) {
    tests := []struct {
        name         string
        typ          string
        password     string
        hashSegments int
        hashLength   int
        wantErr      bool
    }{
        {"Should Work", "argon2id", "Password1", 6, 118, false},
        {"Should Not Work", "argon2id", "", 1, 0, true},
        {"Should Work 2", "argon2id", "gS</5Tu>3@(<FCtY", 6, 118, false},
        {"Should Work 3", "argon2id", `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, 6, 118, false},
        {"Should Work 31", "argon2i", `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, 6, 117, false},
        {"Should Not Work 2", "argon2i", "", 1, 0, true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := GenerateSaltedHashWithType(rand.Reader, tt.password, tt.typ)
            hashSegments := strings.Split(got, "$")
            if (err != nil) != tt.wantErr {
                t.Errorf("GenerateSaltedHashWithType() = %v, want %v", err, tt.wantErr)
                return
            }

            if len(hashSegments) != tt.hashSegments {
                t.Errorf("GenerateSaltedHashWithType() had %d segments. Want %d", len(hashSegments), tt.hashSegments)
            }

            if len(got) != tt.hashLength {
                t.Errorf("GenerateSaltedHashWithType() hash length = %v, want %v", len(got), tt.hashLength)
            }
        })
    }
}

func Test_CompareHashWithPassword_Check(t *testing.T) {
    tests := []struct {
        name     string
        hash     string
        password string
        isValid  bool
        wantErr  bool
    }{
        {"Should Work 1", `$argon2i$v=19$m=8,t=1,p=1$YWFhYWFhYWE$3ney028aI7naIJ/5U///1ICfSVF0Ta4jh2SpJ1jhsCE`, `pass`, true, false},
        {"Should Work 2", `$argon2id$v=19$m=8,t=1,p=1$YWFhYWFhYWE$tPAla38/iYe0rtvQKVaPv04WYar67QEGlc4fhxU185s`, `pass`, true, false},
        {"Should Work 3", `$argon2d$v=19$m=8,t=1,p=1$YWFhYWFhYWE$0WM+IC/fpCF2boiNXmu0lnBXDAKes/BHiYuq9abKsWQ`, `pass`, true, false},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := CompareHashWithPassword(tt.hash, tt.password)
            if (err != nil) != tt.wantErr {
                t.Errorf("CompareHashWithPassword() error = %v, wantErr %v", err, tt.wantErr)
                t.Errorf("hash is %v", got)
                return
            }

            if got != tt.isValid {
                t.Errorf("CompareHashWithPassword() = %v, want %v", got, tt.isValid)
            }
        })
    }
}

type testReader struct {
    k []byte
}

func newTestReader(k []byte) *testReader {
    return &testReader{k}
}

func (this *testReader) Read(dst []byte) (n int, err error) {
    copy(dst, this.k)

    return len(dst), nil
}

func Test_GenerateSaltedHashWithTypeAndOpt_Check(t *testing.T) {
    {
        salt1 := fromHex("313233343536373839616263646566")

        res1, _ := GenerateSaltedHashWithTypeAndOpt(newTestReader(salt1), "pass", "argon2id", Opt{
            SaltLen: len(salt1),
            Time:    1,
            Memory:  8,
            Threads: 1,
            KeyLen:  32,
        })

        check1 := "$argon2id$v=19$m=8,t=1,p=1$MTIzNDU2Nzg5YWJjZGVm$+iAchMa6urtGUvqS2c2ly5SxSb3Jj9S/nq4SZaIgLaI"
        if check1 != res1 {
            t.Errorf("argon2id fail, got %s, want %s", res1, check1)
        }
    }

    {
        salt1 := fromHex("313233343536373839616263646566")

        res1, _ := GenerateSaltedHashWithTypeAndOpt(newTestReader(salt1), "pass", "argon2i", Opt{
            SaltLen: len(salt1),
            Time:    3,
            Memory:  8192,
            Threads: 1,
            KeyLen:  32,
        })

        check1 := "$argon2i$v=19$m=8192,t=3,p=1$MTIzNDU2Nzg5YWJjZGVm$7iO3QHobBZHBgjSM+u92dRHJeKpsMdbZ+sLxPjcm9MI"
        if check1 != res1 {
            t.Errorf("argon2i fail, got %s, want %s", res1, check1)
        }
    }

    {
        salt1 := fromHex("313233343536373839616263646566")

        res1, _ := GenerateSaltedHashWithTypeAndOpt(newTestReader(salt1), "pass", "argon2d", Opt{
            SaltLen: len(salt1),
            Time:    3,
            Memory:  8192,
            Threads: 1,
            KeyLen:  32,
        })

        check1 := "$argon2d$v=19$m=8192,t=3,p=1$MTIzNDU2Nzg5YWJjZGVm$6C4pewOLgibFqWOo9mKTN2xV8KBRq7wjD8PM7DsoV0k"
        if check1 != res1 {
            t.Errorf("argon2d fail, got %s, want %s", res1, check1)
        }
    }
}
