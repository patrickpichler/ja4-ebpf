package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/patrickpichler/ebpf-ja4plus-fingerprinting/pkg/cgroup"
	"github.com/patrickpichler/ebpf-ja4plus-fingerprinting/pkg/ja4"
)

type TracerCfg struct {
}

type Tracer struct {
	log        *slog.Logger
	objs       *tracerObjects
	loaded     atomic.Bool
	cgroupLink link.Link
	cfg        TracerCfg
}

func New(log *slog.Logger, cfg TracerCfg) (Tracer, error) {
	return Tracer{
		log: log,
		cfg: cfg,
	}, nil
}

func (t *Tracer) load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("error while removing memlock: %w", err)
	}

	spec, err := loadTracer()
	if err != nil {
		return fmt.Errorf("error while loading bpf spec: %w", err)
	}

	objs := tracerObjects{}
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.log.Error(fmt.Sprintf("Verifier error: %+v", ve))
		}

		return fmt.Errorf("error while loading and assigning tracer objs: %w", err)
	}

	t.objs = &objs

	t.loaded.Store(true)

	return nil
}

func (t *Tracer) attach() error {
	if !t.loaded.Load() {
		return errors.New("tracer needs to be loaded before it can be attached")
	}

	cgroupPath, err := cgroup.DetectCgroupPath()
	if err != nil {
		return fmt.Errorf("cannot get cgroup path: %w", err)
	}

	cgroupLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: t.objs.HandleEgress,
	})
	if err != nil {
		return fmt.Errorf("error while attaching link: %w", err)
	}

	t.cgroupLink = cgroupLink

	return nil
}

func (t *Tracer) Init() error {
	if err := t.load(); err != nil {
		return fmt.Errorf("error loading tracer: %w", err)
	}

	if err := t.attach(); err != nil {
		return fmt.Errorf("error attaching tracer: %w", err)
	}

	return nil
}

func (t *Tracer) Run(ctx context.Context) error {
	eventReader, err := ringbuf.NewReader(t.objs.Events)
	if err != nil {
		return fmt.Errorf("error while creating perf array reader: %w", err)
	}

	go func() {
		// We need this goroutine as otherwise we might end forever in case of a SIGTERM.
		<-ctx.Done()
		eventReader.Close()
	}()

	var record ringbuf.Record
	var event tracerEvent

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := eventReader.ReadInto(&record)
		if err != nil {
			return fmt.Errorf("error reading from perf array: %w", err)
		}

		r := bytes.NewReader(record.RawSample)

		if err := binary.Read(r, binary.LittleEndian, &event); err != nil {
			t.log.Error("error while parsing event from perf array",
				slog.Any("error", err))
			continue
		}

		currentPos, err := r.Seek(0, io.SeekCurrent)
		if err != nil {
			t.log.Error("error while finding current offset in buffer",
				slog.Any("error", err))
			continue
		}

		payloadEnd := currentPos + int64(event.PayloadSize)
		if len(record.RawSample) < int(payloadEnd) {
			t.log.Error("malformed payload",
				slog.Any("error", "payload end is after end of perf array sample"))
			continue
		}

		rawPacket := record.RawSample[currentPos:payloadEnd]

		fingerprint, err := parseTLSPacket(event, rawPacket)
		if err != nil {
			t.log.Error("error parsing tls packet",
				slog.Any("error", err))
			continue
		}

		t.log.Info("got tls client_hello",
			slog.Uint64("size", uint64(event.PayloadSize)),
			slog.String("fingerprint", fingerprint.String()),
		)

		continue
	}
}

var (
	ErrUnexpectedEOF = errors.New("unexpected EOF")
)

func parseTLSPacket(event tracerEvent, rawPacket []byte) (ja4.JA4Fingerprint, error) {
	var f ja4.JA4Fingerprint

	// For now only TCP is supported
	f.Protocol = ja4.ProtocolTCP

	decoder := NewDecoder(rawPacket)
	decoder.Skip(9) // Skip record header, as well as parts of the client hello message.

	version, ok := decoder.Uint16()
	if !ok {
		return ja4.JA4Fingerprint{}, fmt.Errorf("error while reading legacy version: %w", ErrUnexpectedEOF)
	}

	f.TLSVersion = ja4.TLSVersion(version)

	decoder.Skip(32) // We don't care about the Random

	if !decoder.SkipUint8Prefixed() { // We do not cate about the session id.
		return ja4.JA4Fingerprint{}, fmt.Errorf("error while reading session id: %w", ErrUnexpectedEOF)
	}

	ciphersuitesDecoder, ok := decoder.Uint16LengthPrefixed()
	if !ok {
		return ja4.JA4Fingerprint{}, fmt.Errorf("error while reading cipher suites: %w", ErrUnexpectedEOF)
	}

	// this works as a single cipher suite is 2 bytes and the length gives the amount of bytes
	numCiphers := ciphersuitesDecoder.Remaining() / 2
	ciphers := make([]ja4.CipherSuite, numCiphers)

	i := 0

	for !ciphersuitesDecoder.Empty() {
		if i >= len(ciphers) {
			return ja4.JA4Fingerprint{}, fmt.Errorf("got more ciphers than expected: got %d, expected %d", i, numCiphers)
		}

		ok := ciphersuitesDecoder.ReadUint16((*uint16)(&ciphers[i]))
		if !ok {
			return ja4.JA4Fingerprint{}, fmt.Errorf("error while reading cipher suite: %w", ErrUnexpectedEOF)
		}

		i++
	}

	f.SetCiphers(ciphers)

	if !decoder.SkipUint8Prefixed() { // We do not care about the legacy compression.
		return ja4.JA4Fingerprint{}, fmt.Errorf("error while reading compression methods length: %w", ErrUnexpectedEOF)
	}

	extensionsDecoder, ok := decoder.Uint16LengthPrefixed()
	if !ok {
		return ja4.JA4Fingerprint{}, fmt.Errorf("error while reading extensions: %w", ErrUnexpectedEOF)
	}

	var extensions []ja4.ExtensionType

	for !extensionsDecoder.Empty() {
		t, ok := extensionsDecoder.Uint16BigEndian()
		if !ok {
			return ja4.JA4Fingerprint{}, fmt.Errorf("error while reading extension: %w", ErrUnexpectedEOF)
		}
		extensionType := ja4.ExtensionType(t)
		switch extensionType {
		case ja4.ExtensionTypeSNI:
			extensionsDecoder.SkipUint16Prefixed() // We do not really care about the SNI data.

			f.SNI = ja4.SNIDomain

		case ja4.ExtensionTypeALPN:
			extensionData, ok := extensionsDecoder.Uint16LengthPrefixed()
			if !ok {
				return ja4.JA4Fingerprint{}, fmt.Errorf("error while reading ALPN extension: %w", ErrUnexpectedEOF)
			}
			alpn, err := parseALPNExtension(extensionData)
			if err != nil {
				return ja4.JA4Fingerprint{}, fmt.Errorf("error while parsing ALPN extension: %w", err)
			}
			f.ALPNValue = alpn

		case ja4.ExtensionTypeSupportedVersions:
			extensionData, ok := extensionsDecoder.Uint16LengthPrefixed()
			if !ok {
				return ja4.JA4Fingerprint{}, fmt.Errorf("error while reading SupportedVersions extension: %w", ErrUnexpectedEOF)
			}
			supportedVersion, err := parseSupportedVersionsExtension(extensionData)
			if err != nil {
				return ja4.JA4Fingerprint{}, fmt.Errorf("error while parsing SupportedVersions extension: %w", err)
			}
			f.TLSVersion = supportedVersion

		case ja4.ExtensionTypeSignatureAlgorithms:
			extensionData, ok := extensionsDecoder.Uint16LengthPrefixed()
			if !ok {
				return ja4.JA4Fingerprint{}, fmt.Errorf("error while reading SupportedVersions extension: %w", ErrUnexpectedEOF)
			}
			signatureAlgos, err := parseSignatureAlgorithmExtension(extensionData)
			if err != nil {
				return ja4.JA4Fingerprint{}, fmt.Errorf("error while parsing SupportedVersions extension: %w", err)
			}

			f.SignatureAlgorithms = signatureAlgos

		default:
			if !extensionsDecoder.SkipUint16Prefixed() { // We do not care about most extensions.
				return ja4.JA4Fingerprint{}, fmt.Errorf("error while parsing extension 0x%s: %w", extensionType.Hex(), ErrUnexpectedEOF)
			}
		}

		extensions = append(extensions, extensionType)
		continue
	}

	f.SetExtensions(extensions)

	return f, nil
}

func parseALPNExtension(data *Decoder) (ja4.ALPNValue, error) {
	data, ok := data.Uint16LengthPrefixed()
	if !ok {
		return ja4.ALPNValue{'0', '0'}, fmt.Errorf("error while reading ALPN data: %w", ErrUnexpectedEOF)
	}

	if data.Remaining() == 0 {
		return ja4.ALPNValue{'0', '0'}, nil
	}

	firstALPNLen, ok := data.Uint8()
	if !ok {
		return ja4.ALPNValue{'0', '0'}, fmt.Errorf("error while reading first ALPN len: %w", ErrUnexpectedEOF)
	}

	rawData, ok := data.Slice(int(firstALPNLen))
	if !ok {
		return ja4.ALPNValue{'0', '0'}, fmt.Errorf("error while reading first ALPN data: %w", ErrUnexpectedEOF)
	}

	if firstALPNLen == 1 {
		if isAlphaNumeric(rawData[0]) {
			return ja4.ALPNValue{rawData[0], rawData[0]}, nil
		} else {
			h := hex.EncodeToString(rawData)
			return ja4.ALPNValue{h[0], h[0]}, nil
		}
	}

	if isAlphaNumeric(rawData[0]) && isAlphaNumeric(rawData[len(rawData)-1]) {
		return ja4.ALPNValue{rawData[0], rawData[len(rawData)-1]}, nil
	}

	h := hex.EncodeToString(rawData)

	return ja4.ALPNValue{h[0], h[len(h)-1]}, nil
}

func isAlphaNumeric(b byte) bool {
	return (b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z')
}

func parseSupportedVersionsExtension(data *Decoder) (ja4.TLSVersion, error) {
	data, ok := data.Uint8LengthPrefixed()
	if !ok {
		return 0, fmt.Errorf("error while reading supported versions: %w", ErrUnexpectedEOF)
	}

	var latestVersion uint16

	for !data.Empty() {
		v, ok := data.Uint16BigEndian()
		if !ok {
			return 0, fmt.Errorf("error while reading supported version: %w", ErrUnexpectedEOF)
		}

		if v > latestVersion {
			latestVersion = v
		}
	}

	return ja4.TLSVersion(latestVersion), nil
}

func parseSignatureAlgorithmExtension(data *Decoder) ([]ja4.SignatureAlgorithm, error) {
	data, ok := data.Uint16LengthPrefixed()
	if !ok {
		return nil, fmt.Errorf("error while reading signature algorithms: %w", ErrUnexpectedEOF)
	}

	// this works as a single signature algorithm is 2 bytes and the length gives the amount of bytes
	numAlgos := data.Remaining() / 2
	algos := make([]ja4.SignatureAlgorithm, numAlgos)

	i := 0

	for !data.Empty() {
		if i >= len(algos) {
			return nil, fmt.Errorf("got more signature algorithms than expected: got %d, expected %d", i, numAlgos)
		}

		ok := data.ReadUint16((*uint16)(&algos[i]))
		if !ok {
			return nil, fmt.Errorf("error while reading signature algorithms: %w", ErrUnexpectedEOF)
		}

		i++
	}

	return algos, nil
}
