// Copyright 2026 The age-plugin-sshagent Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"golang.org/x/crypto/ssh/agent"
)

func captureCommand(t *testing.T, run func() int) (int, string, string) {
	t.Helper()
	stdout, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	stderr, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdout, stderr
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
	code := run()
	read := func(f *os.File) string {
		t.Helper()
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(f)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	return code, read(stdout), read(stderr)
}

func TestKeygenEscapesComments(t *testing.T) {
	attacker, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	comment := "work\r\n" + attacker.String() + "\n#\x1b[2J\x00\t"
	kr, _ := newTestAgent(t, comment)
	serveAgent(t, kr)
	path := filepath.Join(t.TempDir(), "identity.txt")
	code, stdout, stderr := captureCommand(t, func() int {
		return cmdKeygen([]string{"-o", path})
	})
	if code != 0 {
		t.Fatalf("keygen returned %d: %s", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("unexpected stdout: %q", stdout)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected exactly four output lines, got %d", len(lines))
	}
	if !strings.HasSuffix(lines[1], " "+strconv.Quote(comment)) {
		t.Fatalf("comment was not escaped: %q", lines[1])
	}
	name, data, err := plugin.ParseIdentity(lines[3])
	if err != nil || name != pluginName {
		t.Fatalf("invalid plugin identity: %q, %v", name, err)
	}
	id, err := deriveFromPayload(data)
	if err != nil {
		t.Fatal(err)
	}
	recipient := id.Recipient().String()
	if lines[2] != "# public key: "+recipient || stderr != "Public key: "+recipient+"\n" {
		t.Fatal("reported recipient does not match the saved identity")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("identity file accessible to other users: %v", info.Mode())
	}
	before := string(b)
	code, _, stderr = captureCommand(t, func() int {
		return cmdKeygen([]string{"-o", path})
	})
	if code == 0 || strings.Contains(stderr, "Public key:") {
		t.Fatalf("existing output file reported success: %d, %s", code, stderr)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != before {
		t.Fatalf("existing identity file was modified: %v", err)
	}
}

func TestCommandsReportWriteFailures(t *testing.T) {
	kr, key := newTestAgent(t, "write-failure")
	serveAgent(t, kr)
	d, err := newIdentityData(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(path, []byte(plugin.EncodeIdentity(pluginName, d.encode())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		run  func() int
	}{
		{"keygen", func() int { return cmdKeygen(nil) }},
		{"list", func() int { return cmdList(nil) }},
		{"recipient", func() int { return cmdRecipient([]string{"-i", path}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			readOnly, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer readOnly.Close()
			code, _, stderr := captureCommand(t, func() int {
				old := os.Stdout
				os.Stdout = readOnly
				defer func() { os.Stdout = old }()
				return tc.run()
			})
			if code == 0 || !strings.Contains(stderr, "age-plugin-sshagent:") {
				t.Fatalf("output failure not reported: %d, %s", code, stderr)
			}
			if strings.Contains(stderr, "Public key:") {
				t.Fatalf("output failure reported success: %s", stderr)
			}
		})
	}
}

func TestKeyCommentsEscapedInListAndErrors(t *testing.T) {
	comment := "work\nforged\x1b[2J"
	kr, _ := newTestAgent(t, comment)
	serveAgent(t, kr)
	code, stdout, stderr := captureCommand(t, func() int { return cmdList(nil) })
	if code != 0 || strings.Count(stdout, "\n") != 1 || !strings.Contains(stdout, strconv.Quote(comment)) {
		t.Fatalf("list did not escape comment: %d, %q, %s", code, stdout, stderr)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Add(agent.AddedKey{PrivateKey: priv, Comment: comment}); err != nil {
		t.Fatal(err)
	}
	_, err = pickKey(kr, "")
	if err == nil || strings.Count(err.Error(), "\n") != 2 || strings.Count(err.Error(), strconv.Quote(comment)) != 2 {
		t.Fatalf("ambiguous-key error did not escape comments: %v", err)
	}
}
