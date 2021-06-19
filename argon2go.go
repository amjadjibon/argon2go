package argon2go

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
)

type Argon2Hash struct {
	Algorithm   string
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func GenerateRandomBytes(byteLen uint32) ([]byte, error) {
	bytes := make([]byte, byteLen)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func (a *Argon2Hash) GenerateHashFromPassword(password string, salt []byte) (string, error) {
	hash := argon2.IDKey([]byte(password), salt, a.Iterations, a.Memory, a.Parallelism, a.KeyLength)

	// Base64 encode the salt and hashed password.
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		"argon2id", argon2.Version, a.Memory, a.Iterations, a.Parallelism, b64Salt, b64Hash)
	return encodedHash, nil
}

func (a *Argon2Hash) ComparePasswordAndHash(password string, encodedHash string) (bool, error) {
	splitHash := strings.Split(encodedHash, "$")
	if len(splitHash) != 6 {
		return false, errors.New("invalid hash")
	}
	if splitHash[1] != "argon2id" {
		return false, errors.New("invalid algorithm")
	}
	var version int

	_, err := fmt.Sscanf(splitHash[2], "v=%d", &version)
	if err != nil {
		return false, err
	}

	if version != argon2.Version {
		return false, errors.New("incompatible version")
	}
	_, err = fmt.Sscanf(splitHash[3], "m=%d,t=%d,p=%d", &a.Memory, &a.Iterations, &a.Parallelism)

	if err != nil {
		return false, errors.New("incompatible version")
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(splitHash[4])
	if err != nil {
		return false, err
	}

	a.SaltLength = uint32(len(salt))

	decodedHash, err := base64.RawStdEncoding.Strict().DecodeString(splitHash[5])
	if err != nil {
		return false, err
	}

	a.KeyLength = uint32(len(decodedHash))

	hash := argon2.IDKey([]byte(password), salt, a.Iterations, a.Memory, a.Parallelism, a.KeyLength)

	if subtle.ConstantTimeCompare(hash, decodedHash) == 1 {
		return true, nil
	}
	return hmac.Equal(hash, decodedHash), nil
}

func Encode(
	password string,
	algorithm string,
	memory uint32,
	iteration uint32,
	parallelism uint8,
	saltLen uint32,
	keyLen uint32) (string, error) {

	if algorithm != "argon2" {
		return "", errors.New("algorithm must be argon2")
	}
	if len(password) == 0 {
		return "", errors.New("len of password can not be zero")
	}

	argon2Hash := &Argon2Hash{
		Algorithm:   algorithm,
		Memory:      memory,
		Iterations:  iteration,
		Parallelism: parallelism,
		SaltLength:  saltLen,
		KeyLength:   keyLen,
	}

	salt, err := GenerateRandomBytes(argon2Hash.SaltLength)
	if err != nil {
		return "", err
	}

	encodedHash, err := argon2Hash.GenerateHashFromPassword(password, salt)
	if err != nil {
		return "", err
	}

	return encodedHash, nil
}

func Verify(password string, hash string) (bool, error) {
	argon2Hash := &Argon2Hash{}
	return argon2Hash.ComparePasswordAndHash(password, hash)
}
