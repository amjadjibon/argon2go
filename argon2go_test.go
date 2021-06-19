package argon2go

import (
	"fmt"
	"testing"
)

func TestGenerateRandomBytes(t *testing.T) {
	bytes, err := generateRandomBytes(16)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(bytes)
}

func TestEncode(t *testing.T) {
	encode, err := Encode("1234", "argon2", 64*1024, 4, 4, 16, 32)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(encode)
}

func TestDecode(t *testing.T) {
	decode, err := Verify("1234", "$argon2id$v=19$m=65536,t=4,p=4$isto+IIDInnOpcTfYI+TKQ$SNF1eocm0AqLkkTXdXtLxA4ErUhty33uZM+bO0+Vp/c")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(decode)
}
