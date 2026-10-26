//go:build !windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/internal/packet"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/unix"
)

type stdio struct {
	input, output *os.File
}

func (s stdio) Read(b []byte) (int, error)  { return s.input.Read(b) }
func (s stdio) Write(b []byte) (int, error) { return s.output.Write(b) }
func (s stdio) Close() error                { return errors.Join(s.input.Close(), s.output.Close()) }

func packetPipe(file *os.File) (*os.File, error) {
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	// Inherited blocking stdio is not registered with Go's poller. Adopt owned
	// nonblocking descriptors so Close interrupts pending reads and writes.
	if err = unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), file.Name()), nil
}

type packetDevice struct {
	stream *packet.Stream
	events chan tun.Event
	done   chan error
	ready  <-chan struct{}
	once   sync.Once
}

func (*packetDevice) File() *os.File             { return nil }
func (*packetDevice) MTU() (int, error)          { return 1380, nil }
func (*packetDevice) Name() (string, error)      { return "packet-stdio", nil }
func (*packetDevice) BatchSize() int             { return 1 }
func (t *packetDevice) Events() <-chan tun.Event { return t.events }
func (t *packetDevice) Close() error {
	return t.finish(nil)
}
func (t *packetDevice) finish(cause error) error {
	var err error
	t.once.Do(func() { err = t.stream.Close(); close(t.events); t.done <- cause })
	return err
}
func (t *packetDevice) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	data, err := t.stream.ReadPacket()
	if err != nil {
		_ = t.finish(err)
		if errors.Is(err, io.EOF) {
			return 0, os.ErrClosed
		}
		return 0, err
	}
	if len(buffers) == 0 || len(sizes) == 0 || offset < 0 || len(buffers[0])-offset < len(data) {
		return 0, io.ErrShortBuffer
	}
	sizes[0] = copy(buffers[0][offset:], data)
	return 1, nil
}
func (t *packetDevice) Write(buffers [][]byte, offset int) (int, error) {
	if t.ready != nil {
		select {
		case <-t.ready:
		case <-t.events:
			return 0, os.ErrClosed
		}
	}
	for i, data := range buffers {
		if offset < 0 || offset >= len(data) {
			return i, io.ErrShortBuffer
		}
		if err := t.stream.WritePacket(data[offset:]); err != nil {
			_ = t.finish(err)
			return i, err
		}
	}
	return len(buffers), nil
}

func runPacketMode(configPath string) error {
	file, err := os.Open(configPath)
	if err != nil {
		return errors.New("open private UAPI configuration")
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	_ = file.Close()
	defer clear(data)
	if err != nil || len(data) == 0 || len(data) > 1<<20 {
		return errors.New("invalid UAPI configuration size")
	}
	input, err := packetPipe(os.Stdin)
	if err != nil {
		return errors.New("adopt packet input pipe")
	}
	output, err := packetPipe(os.Stdout)
	if err != nil {
		_ = input.Close()
		return errors.New("adopt packet output pipe")
	}
	ready := make(chan struct{})
	t := &packetDevice{stream: packet.New(stdio{input, output}), events: make(chan tun.Event), done: make(chan error, 1), ready: ready}
	native := device.NewDevice(t, conn.NewDefaultBind(), &device.Logger{Verbosef: device.DiscardLogf, Errorf: func(string, ...any) {
		fmt.Fprintln(os.Stderr, "ERROR AmneziaWG: native device operation failed")
	}})
	defer native.Close()
	if err = native.IpcSet(string(data)); err != nil {
		return errors.New("AmneziaWG rejected the UAPI configuration")
	}
	clear(data)
	if err = native.Up(); err != nil {
		return errors.New("start AmneziaWG device")
	}
	stopping := make(chan os.Signal, 1)
	signal.Notify(stopping, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(stopping)
	if _, err = io.WriteString(output, "RDY\n"); err != nil {
		return err
	}
	close(ready)
	select {
	case err := <-t.done:
		if err != nil && !errors.Is(err, io.EOF) {
			return errors.New("packet stream failed")
		}
	case <-stopping:
	}
	return t.Close()
}
