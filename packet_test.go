//go:build !windows

package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/internal/packet"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// Exercise the actual CLI without creating an OS TUN, routes or UAPI socket.
func TestPacketMode(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "amneziawg-go")
	buildArgs := []string{"build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", binary}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "-race" && setting.Value == "true" {
				buildArgs = append(buildArgs, "-race")
			}
		}
	}
	build := exec.Command("go", append(buildArgs, ".")...)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build packet-mode CLI: %v\n%s", err, output)
	}
	t.Run("encrypted_round_trip", func(t *testing.T) { testPacketRoundTrip(t, binary) })
	t.Run("shutdown_and_framing", func(t *testing.T) { testPacketShutdown(t, binary) })
	t.Run("configuration_rejection", func(t *testing.T) { testPacketConfiguration(t, binary) })
}

func testPacketRoundTrip(t *testing.T, binary string) {
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverIO, wire := net.Pipe()
	defer wire.Close()
	_ = wire.SetDeadline(time.Now().Add(10 * time.Second))
	serverTun := &packetDevice{stream: packet.New(serverIO), events: make(chan tun.Event), done: make(chan error, 1)}
	server := device.NewDevice(serverTun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer server.Close()
	err = server.IpcSet("private_key=" + hex.EncodeToString(serverKey.Bytes()) + "\nlisten_port=0\npublic_key=" + hex.EncodeToString(clientKey.PublicKey().Bytes()) + "\nallowed_ip=10.73.0.2/32\nallowed_ip=fd73::2/128\n")
	if err != nil {
		t.Fatal("configure native server")
	}
	if err = server.Up(); err != nil {
		t.Fatal(err)
	}
	state, err := server.IpcGet()
	if err != nil {
		t.Fatal("inspect native server port")
	}
	port := ""
	for _, line := range strings.Split(state, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port = strings.TrimPrefix(line, "listen_port=")
		}
	}
	if port == "" || port == "0" {
		t.Fatal("native server did not bind")
	}
	config := "private_key=" + hex.EncodeToString(clientKey.Bytes()) + "\npublic_key=" + hex.EncodeToString(serverKey.PublicKey().Bytes()) + "\nallowed_ip=10.73.0.1/32\nallowed_ip=fd73::1/128\nendpoint=127.0.0.1:" + port + "\n"
	command, input, output := startPacketProcess(t, binary, config)
	client := packet.New(&fixturePipe{Reader: output, Writer: input})
	serverPackets := packet.New(wire)
	for _, family := range []byte{4, 6} {
		request := make([]byte, 28)
		request[0], request[8], request[9] = 0x45, 64, 253

		copy(request[12:16], []byte{10, 73, 0, 2})
		copy(request[16:20], []byte{10, 73, 0, 1})
		copy(request[20:], "PACKETIO")
		if family == 6 {
			request = make([]byte, 48)
			request[0], request[6], request[7] = 0x60, 253, 64
			request[5] = 8
			copy(request[8:24], net.ParseIP("fd73::2").To16())
			copy(request[24:40], net.ParseIP("fd73::1").To16())
			copy(request[40:], "PACKETIO")
		} else {
			request[3] = byte(len(request))
		}
		if err = client.WritePacket(request); err != nil {
			t.Fatal(err)
		}
		actual, err := serverPackets.ReadPacket()
		if err != nil || !bytes.Equal(actual, request) {
			t.Fatal("native encrypted upload did not round-trip")
		}
		response := append([]byte{}, request...)
		if family == 4 {
			copy(response[12:16], request[16:20])
			copy(response[16:20], request[12:16])
		} else {
			copy(response[8:24], request[24:40])
			copy(response[24:40], request[8:24])
		}
		if err = serverPackets.WritePacket(response); err != nil {
			t.Fatal(err)
		}
		actual, err = client.ReadPacket()
		if err != nil || !bytes.Equal(actual, response) {
			t.Fatal("native encrypted download did not round-trip")
		}
	}
	_ = input.Close()
	if err = command.Wait(); err != nil {
		t.Fatal("packet mode did not stop on pipe EOF")
	}
}

func startPacketProcess(t *testing.T, binary, config string) (*exec.Cmd, io.WriteCloser, io.ReadCloser) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "client.uapi")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, binary, "--packet-stdio", path)
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGQUIT) }
	command.WaitDelay = time.Second
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close(); _ = command.Process.Kill(); _ = command.Wait() })
	var marker [4]byte
	if _, err := io.ReadFull(output, marker[:]); err != nil || string(marker[:]) != "RDY\n" {
		t.Fatal("packet-mode readiness failed")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal("startup configuration is still required after readiness", err)
	}
	return command, input, output
}

func testPacketShutdown(t *testing.T, binary string) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := "private_key=" + hex.EncodeToString(key.Bytes()) + "\n"
	for _, test := range []struct {
		name    string
		frame   []byte
		signal  bool
		failure bool
	}{
		{name: "EOF"},
		{name: "SIGTERM", signal: true},
		{name: "zero_length", frame: []byte{0, 0, 0, 0}, failure: true},
		{name: "oversized", frame: []byte{0, 1, 0, 0}, failure: true},
		{name: "truncated_header", frame: []byte{0}, failure: true},
		{name: "missing_packet", frame: []byte{0, 0, 0, 20}, failure: true},
		{name: "truncated_packet", frame: []byte{0, 0, 0, 20, 0x45}, failure: true},
		{name: "invalid_IP", frame: append([]byte{0, 0, 0, 20}, make([]byte, 20)...), failure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			command, input, output := startPacketProcess(t, binary, config)
			if len(test.frame) > 0 {
				if _, err := input.Write(test.frame); err != nil {
					t.Fatal(err)
				}
			}
			if test.signal {
				if err := command.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			} else {
				_ = input.Close()
			}
			trailing, err := io.ReadAll(output)
			if err != nil || len(trailing) != 0 {
				t.Fatal("stdout contains non-packet output", err)
			}
			if err := command.Wait(); (err != nil) != test.failure {
				t.Fatalf("unexpected packet-mode exit: %v", err)
			}
		})
	}
}

func testPacketConfiguration(t *testing.T, binary string) {
	for _, config := range []string{"", "unknown=REDACTED\n", strings.Repeat("x", (1<<20)+1)} {
		path := filepath.Join(t.TempDir(), "invalid.uapi")
		if err := os.WriteFile(path, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(binary, "--packet-stdio", path)
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		if err := command.Run(); err == nil || stdout.Len() != 0 || strings.Contains(stderr.String(), "REDACTED") {
			t.Fatal("invalid configuration was accepted, signalled readiness or leaked")
		}
	}
	command := exec.Command(binary, "--packet-stdio")
	if err := command.Run(); err == nil {
		t.Fatal("missing configuration was accepted")
	}
}

type fixturePipe struct {
	io.Reader
	io.Writer
}

func (p *fixturePipe) Close() error { return p.Writer.(io.Closer).Close() }
