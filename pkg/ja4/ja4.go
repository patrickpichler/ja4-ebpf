package ja4

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
)

type Protocol uint8

const (
	ProtocolTCP   Protocol = 't'
	ProtocolQuick Protocol = 'q'
)

type TLSVersion uint16

func (c TLSVersion) IsGrease() bool {
	return c&0x0F0F == 0x0A0A && ((c&0xF000)>>8 == c&0xF0)
}
func (c TLSVersion) Hex() string {
	return hex.EncodeToString([]byte{byte(c >> 8), byte(c)})
}

func (c TLSVersion) Bytes() []byte {
	return []byte{byte(c >> 8), byte(c)}
}

const (
	TLSVersionUnknown  TLSVersion = 0
	TLSVersionSSL2     TLSVersion = 0x0002
	TLSVersionSSL3     TLSVersion = 0x0300
	TLSVersion1_0      TLSVersion = 0x0301
	TLSVersion1_1      TLSVersion = 0x0302
	TLSVersion1_2      TLSVersion = 0x0303
	TLSVersion1_3      TLSVersion = 0x0304
	TLSVersionDTLS_1_0 TLSVersion = 0xfeff
	TLSVersionDTLS_1_2 TLSVersion = 0xfefd
	TLSVersionDTLS_1_3 TLSVersion = 0xfefc
)

type SNI uint8

const (
	SNIIP     SNI = 0
	SNIDomain SNI = 1
)

type ALPNValue [2]byte

type SignatureAlgorithm uint16

func (c SignatureAlgorithm) Hex() string {
	return hex.EncodeToString([]byte{byte(c), byte(c >> 8)})
}

func (c SignatureAlgorithm) Bytes() []byte {
	return []byte{byte(c >> 8), byte(c)}
}

const (
	ExtensionTypeSNI                 ExtensionType = 0
	ExtensionTypeSignatureAlgorithms ExtensionType = 13
	ExtensionTypeALPN                ExtensionType = 16
	ExtensionTypeSupportedVersions   ExtensionType = 43
)

type ExtensionType uint16

func (c ExtensionType) IsGrease() bool {
	return c&0x0F0F == 0x0A0A && ((c&0xF000)>>8 == c&0xF0)
}
func (c ExtensionType) Hex() string {
	return hex.EncodeToString([]byte{byte(c >> 8), byte(c)})
}

func (c ExtensionType) Bytes() []byte {
	return []byte{byte(c >> 8), byte(c)}
}

type CipherSuite uint16

func (c CipherSuite) IsGrease() bool {
	return c&0x0F0F == 0x0A0A && ((c&0xF000)>>8 == c&0xF0)
}
func (c CipherSuite) Hex() string {
	return hex.EncodeToString([]byte{byte(c), byte(c >> 8)})
}

func (c CipherSuite) Bytes() []byte {
	return []byte{byte(c >> 8), byte(c)}
}

type JA4Fingerprint struct {
	Protocol            Protocol
	TLSVersion          TLSVersion
	SNI                 SNI
	NumCipherSuites     uint8
	NumExtensions       uint8
	ALPNValue           ALPNValue
	CipherSuites        []CipherSuite
	Extensions          []ExtensionType
	SignatureAlgorithms []SignatureAlgorithm
	ExtensionsAlgoHash  [sha256.Size]byte
}

func (f *JA4Fingerprint) SetCiphers(c []CipherSuite) {
	suites := make([]CipherSuite, 0, len(c))
	for _, cs := range c {
		if cs.IsGrease() {
			continue
		}

		suites = append(suites, cs)
	}

	slices.SortFunc(suites, func(a, b CipherSuite) int {
		return strings.Compare(a.Hex(), b.Hex())
	})

	f.CipherSuites = suites
	f.NumCipherSuites = uint8(len(suites))
}

func (f *JA4Fingerprint) SetExtensions(e []ExtensionType) {
	extensions := make([]ExtensionType, 0, len(e))
	nonGreaseFilteredOut := 0

	for _, et := range e {
		if et.IsGrease() {
			continue
		}

		switch et {
		case ExtensionTypeALPN, ExtensionTypeSNI:
			nonGreaseFilteredOut++
			continue
		}

		extensions = append(extensions, et)
	}

	slices.SortFunc(extensions, func(a, b ExtensionType) int {
		return strings.Compare(a.Hex(), b.Hex())
	})

	f.Extensions = extensions
	f.NumExtensions = uint8(len(extensions) + nonGreaseFilteredOut)
}

func (f JA4Fingerprint) cipherSuitesRaw() string {
	ciphers := make([]string, len(f.CipherSuites), len(f.CipherSuites))

	for i, c := range f.CipherSuites {
		ciphers[i] = c.Hex()
	}

	return strings.Join(ciphers, ",")
}

func (f JA4Fingerprint) cipherSuitesHash() string {
	hash := sha256.Sum256([]byte(f.cipherSuitesRaw()))

	return hex.EncodeToString(hash[:])[:12]
}

func (f JA4Fingerprint) extensionsRaw() string {
	extenions := make([]string, len(f.Extensions), len(f.Extensions))

	for i, e := range f.Extensions {
		extenions[i] = e.Hex()
	}

	return strings.Join(extenions, ",")
}

func (f JA4Fingerprint) signatureAlgorithmsRaw() string {
	signatureAlgorithms := make([]string, len(f.SignatureAlgorithms), len(f.SignatureAlgorithms))

	for i, e := range f.SignatureAlgorithms {
		signatureAlgorithms[i] = e.Hex()
	}

	return strings.Join(signatureAlgorithms, ",")
}

func (f JA4Fingerprint) thirdPartRaw() string {
	return f.extensionsRaw() + "_" + f.signatureAlgorithmsRaw()
}

func (f JA4Fingerprint) thirdPartHash() string {
	hash := sha256.Sum256([]byte(f.thirdPartRaw()))

	return hex.EncodeToString(hash[:])[:12]
}

func (f JA4Fingerprint) String() string {
	return f.AsString(false)
}

func (f JA4Fingerprint) AsString(raw bool) string {
	var b strings.Builder
	b.Grow(36)

	b.WriteByte(byte(f.Protocol))

	switch f.TLSVersion {
	case TLSVersion1_0:
		b.WriteByte('1')
		b.WriteByte('0')
	case TLSVersion1_1:
		b.WriteByte('1')
		b.WriteByte('1')
	case TLSVersion1_2:
		b.WriteByte('1')
		b.WriteByte('2')
	case TLSVersion1_3:
		b.WriteByte('1')
		b.WriteByte('3')
	case TLSVersionSSL2:
		b.WriteByte('s')
		b.WriteByte('2')
	case TLSVersionSSL3:
		b.WriteByte('s')
		b.WriteByte('3')
	case TLSVersionDTLS_1_0:
		b.WriteByte('d')
		b.WriteByte('1')
	case TLSVersionDTLS_1_2:
		b.WriteByte('d')
		b.WriteByte('2')
	case TLSVersionDTLS_1_3:
		b.WriteByte('d')
		b.WriteByte('3')
	}

	switch f.SNI {
	case SNIDomain:
		b.WriteByte('d')
	case SNIIP:
		b.WriteByte('i')
	default:
		b.WriteByte('0')
	}

	if f.NumCipherSuites > 99 {
		b.WriteString("99")
	} else {
		b.WriteString(strconv.Itoa(int(f.NumCipherSuites)))
	}

	if f.NumExtensions > 99 {
		b.WriteString("99")
	} else {
		b.WriteString(strconv.Itoa(int(f.NumExtensions)))
	}

	if f.ALPNValue[0] == 0 && f.ALPNValue[1] == 0 {
		b.WriteString("00")
	} else {
		b.WriteString(string(f.ALPNValue[:]))
	}

	b.WriteByte('_')

	if raw {
		b.WriteString(f.cipherSuitesRaw())
	} else {
		b.WriteString(f.cipherSuitesHash())
	}

	b.WriteByte('_')

	if raw {
		b.WriteString(f.thirdPartRaw())
	} else {
		b.WriteString(f.thirdPartHash())
	}

	return b.String()
}
