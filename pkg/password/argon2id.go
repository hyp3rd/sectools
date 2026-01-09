package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/hyp3rd/sectools/pkg/converters"
)

const (
	argon2idMinSaltLength = 16
	argon2idMinKeyLength  = 16
	argon2idKiB           = 1024

	argon2idMemoryInteractiveMiB = 64
	argon2idMemoryBalancedMiB    = 128
	argon2idMemoryHighMiB        = 256

	argon2idTimeInteractive = 1
	argon2idTimeBalanced    = 2
	argon2idTimeHigh        = 3

	argon2idDefaultThreads    = 4
	argon2idDefaultSaltLength = argon2idMinSaltLength
	argon2idDefaultKeyLength  = 32

	argon2idPHCPartCount       = 6
	argon2idParamFieldCount    = 3
	argon2idMinMemoryPerThread = 8

	argon2idUint32BitSize = 32
	argon2idUint8BitSize  = 8
)

// Argon2idParams defines parameters for argon2id hashing.
type Argon2idParams struct {
	Memory     uint32
	Time       uint32
	Threads    uint8
	SaltLength uint32
	KeyLength  uint32
}

// Argon2idInteractive returns parameters suitable for latency-sensitive flows.
func Argon2idInteractive() Argon2idParams {
	return Argon2idParams{
		Memory:     argon2idMemoryInteractiveMiB * argon2idKiB,
		Time:       argon2idTimeInteractive,
		Threads:    argon2idDefaultThreads,
		SaltLength: argon2idDefaultSaltLength,
		KeyLength:  argon2idDefaultKeyLength,
	}
}

// Argon2idBalanced returns balanced parameters for general use.
func Argon2idBalanced() Argon2idParams {
	return Argon2idParams{
		Memory:     argon2idMemoryBalancedMiB * argon2idKiB,
		Time:       argon2idTimeBalanced,
		Threads:    argon2idDefaultThreads,
		SaltLength: argon2idDefaultSaltLength,
		KeyLength:  argon2idDefaultKeyLength,
	}
}

// Argon2idHighSecurity returns parameters for high-security environments.
func Argon2idHighSecurity() Argon2idParams {
	return Argon2idParams{
		Memory:     argon2idMemoryHighMiB * argon2idKiB,
		Time:       argon2idTimeHigh,
		Threads:    argon2idDefaultThreads,
		SaltLength: argon2idDefaultSaltLength,
		KeyLength:  argon2idDefaultKeyLength,
	}
}

// Argon2idHasher hashes passwords using argon2id.
type Argon2idHasher struct {
	params Argon2idParams
}

// NewArgon2id constructs a hasher with custom parameters.
func NewArgon2id(params Argon2idParams) (*Argon2idHasher, error) {
	err := params.validate()
	if err != nil {
		return nil, err
	}

	return &Argon2idHasher{params: params}, nil
}

// Hash hashes a password using argon2id and returns a PHC string.
func (h *Argon2idHasher) Hash(password []byte) (string, error) {
	salt := make([]byte, h.params.SaltLength)

	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}

	hash := argon2.IDKey(password, salt, h.params.Time, h.params.Memory, h.params.Threads, h.params.KeyLength)

	return formatArgon2idHash(h.params, salt, hash), nil
}

// Verify checks a password against an encoded hash and reports if it needs rehash.
func (h *Argon2idHasher) Verify(password []byte, encoded string) (ok, needsRehash bool, err error) {
	decoded, err := decodeArgon2idHash(encoded)
	if err != nil {
		return false, false, err
	}

	err = validateArgon2idEncodedParams(decoded.params)
	if err != nil {
		return false, false, err
	}

	keyLength, err := safeUint32FromLen(len(decoded.hash))
	if err != nil {
		return false, false, err
	}

	hash := argon2.IDKey(password, decoded.salt, decoded.params.Time, decoded.params.Memory, decoded.params.Threads, keyLength)

	match := subtle.ConstantTimeCompare(hash, decoded.hash) == 1
	if !match {
		return false, false, nil
	}

	needsRehash = decoded.params.needsRehash(h.params)

	return true, needsRehash, nil
}

func (p Argon2idParams) validate() error {
	if p.Time == 0 || p.Memory == 0 || p.Threads == 0 || p.SaltLength == 0 || p.KeyLength == 0 {
		return ErrInvalidParams
	}

	if p.Memory < argon2idMinMemoryPerThread*uint32(p.Threads) {
		return ErrInvalidParams
	}

	if p.SaltLength < argon2idMinSaltLength || p.KeyLength < argon2idMinKeyLength {
		return ErrInvalidParams
	}

	return nil
}

func validateArgon2idEncodedParams(p Argon2idParams) error {
	if p.Time == 0 || p.Memory == 0 || p.Threads == 0 || p.SaltLength == 0 || p.KeyLength == 0 {
		return ErrInvalidHash
	}

	if p.Memory < argon2idMinMemoryPerThread*uint32(p.Threads) {
		return ErrInvalidHash
	}

	return nil
}

func (p Argon2idParams) needsRehash(target Argon2idParams) bool {
	return p.Memory != target.Memory ||
		p.Time != target.Time ||
		p.Threads != target.Threads ||
		p.SaltLength != target.SaltLength ||
		p.KeyLength != target.KeyLength
}

func formatArgon2idHash(params Argon2idParams, salt, hash []byte) string {
	saltEncoded := base64.RawStdEncoding.EncodeToString(salt)
	hashEncoded := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.Memory,
		params.Time,
		params.Threads,
		saltEncoded,
		hashEncoded,
	)
}

type argon2idDecoded struct {
	params Argon2idParams
	salt   []byte
	hash   []byte
}

func decodeArgon2idHash(encoded string) (argon2idDecoded, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != argon2idPHCPartCount {
		return argon2idDecoded{}, ErrInvalidHash
	}

	if parts[1] != "argon2id" {
		return argon2idDecoded{}, ErrInvalidHash
	}

	versionPart := strings.TrimPrefix(parts[2], "v=")

	version, err := strconv.Atoi(versionPart)
	if err != nil || version != argon2.Version {
		return argon2idDecoded{}, ErrInvalidHash
	}

	params, err := parseArgon2idParams(parts[3])
	if err != nil {
		return argon2idDecoded{}, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return argon2idDecoded{}, ErrInvalidHash
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argon2idDecoded{}, ErrInvalidHash
	}

	saltLength, err := safeUint32FromLen(len(salt))
	if err != nil {
		return argon2idDecoded{}, err
	}

	keyLength, err := safeUint32FromLen(len(hash))
	if err != nil {
		return argon2idDecoded{}, err
	}

	params.SaltLength = saltLength
	params.KeyLength = keyLength

	return argon2idDecoded{
		params: params,
		salt:   salt,
		hash:   hash,
	}, nil
}

func parseArgon2idParams(params string) (Argon2idParams, error) {
	var result Argon2idParams

	fields := strings.Split(params, ",")
	if len(fields) < argon2idParamFieldCount {
		return Argon2idParams{}, ErrInvalidHash
	}

	for _, field := range fields {
		pair := strings.SplitN(field, "=", 2)
		if len(pair) != 2 {
			return Argon2idParams{}, ErrInvalidHash
		}

		switch pair[0] {
		case "m":
			value, err := strconv.ParseUint(pair[1], 10, argon2idUint32BitSize)
			if err != nil {
				return Argon2idParams{}, ErrInvalidHash
			}

			result.Memory = uint32(value)
		case "t":
			value, err := strconv.ParseUint(pair[1], 10, argon2idUint32BitSize)
			if err != nil {
				return Argon2idParams{}, ErrInvalidHash
			}

			result.Time = uint32(value)
		case "p":
			value, err := strconv.ParseUint(pair[1], 10, argon2idUint8BitSize)
			if err != nil {
				return Argon2idParams{}, ErrInvalidHash
			}

			result.Threads = uint8(value)
		default:
			return Argon2idParams{}, ErrInvalidHash
		}
	}

	return result, nil
}

func safeUint32FromLen(length int) (uint32, error) {
	value, err := converters.SafeUint32FromInt64(int64(length))
	if err != nil {
		return 0, ErrInvalidHash
	}

	return value, nil
}
