package tracer

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type Decoder struct {
	buffer []byte
	cursor int
}

func (decoder *Decoder) Buffer() []byte {
	return decoder.buffer
}

func NewDecoder(rawBuffer []byte) *Decoder {
	return &Decoder{
		buffer: rawBuffer,
		cursor: 0,
	}
}

func (decoder *Decoder) Reset(buf []byte) {
	decoder.buffer = buf
	decoder.cursor = 0
}

func (decoder *Decoder) Skip(amount int) bool {
	if decoder.cursor+amount > len(decoder.buffer) {
		return false
	}

	decoder.cursor += amount
	return true
}

func (decoder *Decoder) SkipUint8Prefixed() bool {
	l, ok := decoder.Uint8()
	if !ok {
		return false
	}

	return decoder.Skip(int(l))
}

func (decoder *Decoder) SkipUint16Prefixed() bool {
	l, ok := decoder.Uint16BigEndian()
	if !ok {
		return false
	}

	return decoder.Skip(int(l))
}

func (decoder *Decoder) Empty() bool {
	return decoder.cursor >= len(decoder.buffer)
}

func (decoder *Decoder) Remaining() int {
	return len(decoder.buffer) - decoder.cursor
}

func (decoder *Decoder) ReadUint8(msg *uint8) bool {
	readAmount := 1
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return false
	}
	*msg = decoder.buffer[decoder.cursor]
	decoder.cursor += readAmount
	return true
}

func (decoder *Decoder) Uint8() (uint8, bool) {
	readAmount := 1
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return 0, false
	}
	decoder.cursor += readAmount
	return decoder.buffer[offset], true
}

func (decoder *Decoder) ReadUint16(msg *uint16) bool {
	readAmount := 2
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return false
	}
	*msg = binary.LittleEndian.Uint16(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return true
}

func (decoder *Decoder) Uint16() (uint16, bool) {
	var res uint16
	if !decoder.ReadUint16(&res) {
		return 0, false
	}

	return res, true
}

func (decoder *Decoder) ReadUint16BigEndian(msg *uint16) bool {
	readAmount := 2
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return false
	}
	*msg = binary.BigEndian.Uint16(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return true
}

func (decoder *Decoder) Uint16BigEndian() (uint16, bool) {
	var res uint16
	if !decoder.ReadUint16BigEndian(&res) {
		return 0, false
	}

	return res, true
}

func (decoder *Decoder) ReadUint24(msg *uint32) bool {
	readAmount := 3
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return false
	}
	*msg = uint32(decoder.buffer[offset+0]) | uint32(decoder.buffer[offset+1])<<8 | uint32(decoder.buffer[offset+2])<<16
	decoder.cursor += readAmount
	return true
}

func (decoder *Decoder) ReadUint24BigEndian(msg *uint32) bool {
	readAmount := 3
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return false
	}
	*msg = uint32(decoder.buffer[offset+2]) | uint32(decoder.buffer[offset+1])<<8 | uint32(decoder.buffer[offset])<<16
	decoder.cursor += readAmount
	return true
}

func (decoder *Decoder) Uint24() (uint32, bool) {
	var res uint32
	if !decoder.ReadUint24(&res) {
		return 0, false
	}

	return res, true
}

func (decoder *Decoder) Uint24BigEndian() (uint32, bool) {
	var res uint32
	if !decoder.ReadUint24BigEndian(&res) {
		return 0, false
	}

	return res, true
}

func (decoder *Decoder) ReadUint32(msg *uint32) bool {
	readAmount := 4
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return false
	}
	*msg = binary.LittleEndian.Uint32(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return true
}

func (decoder *Decoder) Uint32() (uint32, bool) {
	var res uint32
	if !decoder.ReadUint32(&res) {
		return 0, false
	}

	return res, true
}

func (decoder *Decoder) ReadUint32BigEndian(msg *uint32) bool {
	readAmount := 4
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return false
	}
	*msg = binary.BigEndian.Uint32(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return true
}

func (decoder *Decoder) ReadUint64(msg *uint64) bool {
	readAmount := 8
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return false
	}
	*msg = binary.LittleEndian.Uint64(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return true
}

func (decoder *Decoder) SubDecoder(readAmount int) (*Decoder, bool) {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return nil, false
	}

	decoder.cursor += readAmount

	return &Decoder{
		buffer: decoder.buffer[offset : offset+readAmount],
	}, true
}

func (decoder *Decoder) Uint8LengthPrefixed() (*Decoder, bool) {
	length, ok := decoder.Uint8()
	if !ok {
		return nil, false
	}

	return decoder.SubDecoder(int(length))
}

func (decoder *Decoder) Uint16LengthPrefixed() (*Decoder, bool) {
	length, ok := decoder.Uint16BigEndian()
	if !ok {
		return nil, false
	}

	return decoder.SubDecoder(int(length))
}

func (decoder *Decoder) Uint24LengthPrefixed() (*Decoder, bool) {
	length, ok := decoder.Uint24()
	if !ok {
		return nil, false
	}

	return decoder.SubDecoder(int(length))
}

func (decoder *Decoder) Uint32LengthPrefixed() (*Decoder, bool) {
	length, ok := decoder.Uint32()
	if !ok {
		return nil, false
	}

	return decoder.SubDecoder(int(length))
}

func (decoder *Decoder) ReadSlice(target []byte, length int) bool {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < length || len(target) < length {
		return false
	}
	decoder.cursor += length
	copy(target, decoder.buffer[offset:offset+length])

	return true
}

func (decoder *Decoder) Slice(length int) ([]byte, bool) {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < length {
		return nil, false
	}
	decoder.cursor += length
	return decoder.buffer[offset : offset+length], true
}

func (decoder *Decoder) Peak(length int) ([]byte, bool) {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < length {
		return nil, false
	}
	return decoder.buffer[offset : offset+length], true
}

func (decoder *Decoder) MustPeak(length int) []byte {
	r, ok := decoder.Peak(length)
	if !ok {
		panic("failed to peak")
	}

	return r
}

func (decoder *Decoder) Dump(length int) {
	r, ok := decoder.Peak(length)
	if !ok {
		panic("failed to peak")
	}

	fmt.Println(hex.Dump(r))
}
