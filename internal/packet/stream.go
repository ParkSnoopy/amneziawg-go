// Package packet carries bounded IP packets over length-delimited byte streams.
package packet

import (
	"encoding/binary"
	"errors"
	"io"

	"sync"
)

// MaxSize bounds allocations for one non-jumbo IP packet.
const MaxSize = 65535

// Stream is a length-delimited, full-duplex packet transport. A single reader and
// concurrent writers are supported. Closing the transport interrupts both sides.
type Stream struct {
	io.ReadWriteCloser
	mu sync.Mutex
}

// New wraps an owned byte stream with length-delimited packet framing.
func New(transport io.ReadWriteCloser) *Stream { return &Stream{ReadWriteCloser: transport} }

// ReadPacket reads and validates one complete IP packet.
func (s *Stream) ReadPacket() ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(s.ReadWriteCloser, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxSize {
		return nil, errors.New("invalid packet frame size")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(s.ReadWriteCloser, data); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if err := Validate(data); err != nil {
		return nil, err
	}
	return data, nil
}

// Validate checks the family and declared length before packet dispatch.
func Validate(data []byte) error {
	if len(data) < 20 || len(data) > MaxSize {
		return errors.New("invalid IP packet size")
	}
	switch data[0] >> 4 {
	case 4:
		header := int(data[0]&15) * 4
		if header < 20 || header > len(data) || int(binary.BigEndian.Uint16(data[2:4])) != len(data) {
			return errors.New("invalid IPv4 packet")
		}
	case 6:
		if len(data) < 40 || int(binary.BigEndian.Uint16(data[4:6]))+40 != len(data) {
			return errors.New("invalid IPv6 packet")
		}
	default:
		return errors.New("unsupported packet family")
	}
	return nil
}

// WritePacket serializes a validated packet without interleaving other writers.
func (s *Stream) WritePacket(data []byte) error {
	if err := Validate(data); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	for _, part := range [][]byte{header[:], data} {
		for len(part) > 0 {
			n, err := s.Write(part)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}
