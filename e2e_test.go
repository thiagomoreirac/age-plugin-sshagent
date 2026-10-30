// Copyright 2026 The age-plugin-sshagent Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// TestAgeCLIEndToEnd drives the real age binary: encrypt with stock age to the
// derived recipient (no plugin involved), then decrypt with `age -d -i` which
// invokes this plugin over the plugin protocol against a live agent socket.
func TestAgeCLIEndToEnd(t *testing.T) {
	ageBin, err := exec.LookPath("age")
	if err != nil {
		t.Skip("age binary not in PATH")
	}

	dir := t.TempDir()
	pluginBin := filepath.Join(dir, "age-plugin-sshagent")
	build := exec.Command("go", "build", "-o", pluginBin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	attacker, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	kr, _ := newTestAgent(t, "e2e@test\n"+attacker.String()+"\n#")
	sock := serveAgent(t, kr)

	identityFile := filepath.Join(dir, "identity.txt")
	code, _, stderr := captureCommand(t, func() int {
		return cmdKeygen([]string{"-o", identityFile})
	})
	if code != 0 {
		t.Fatalf("keygen returned %d: %s", code, stderr)
	}
	contents, err := os.ReadFile(identityFile)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("key comment injected extra lines: got %d", len(lines))
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

	overrides := map[string]string{
		"PATH":          dir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"SSH_AUTH_SOCK": sock,
	}
	var env []string
	for _, e := range os.Environ() {
		key := e
		if i := strings.Index(e, "="); i >= 0 {
			key = e[:i]
		}
		if _, skip := overrides[key]; !skip {
			env = append(env, e)
		}
	}
	for k, v := range overrides {
		env = append(env, k+"="+v)
	}
	plaintext := "end to end via the age CLI"

	// Encrypt: recipient is a native age1..., no plugin needed.
	encrypted := filepath.Join(dir, "msg.age")
	enc := exec.Command(ageBin, "-e", "-r", recipient, "-o", encrypted)
	enc.Stdin = strings.NewReader(plaintext)
	enc.Env = env
	if out, err := enc.CombinedOutput(); err != nil {
		t.Fatalf("age -e: %v\n%s", err, out)
	}

	// Decrypt: age discovers age-plugin-sshagent via PATH.
	dec := exec.Command(ageBin, "-d", "-i", identityFile, encrypted)
	dec.Env = env
	var stdout, decStderr bytes.Buffer
	dec.Stdout, dec.Stderr = &stdout, &decStderr
	if err := dec.Run(); err != nil {
		t.Fatalf("age -d: %v\n%s", err, decStderr.String())
	}
	if stdout.String() != plaintext {
		t.Errorf("got %q, want %q", stdout.String(), plaintext)
	}

	encWithIdentity := exec.Command(ageBin, "-e", "-i", identityFile)
	encWithIdentity.Stdin = strings.NewReader(plaintext)
	encWithIdentity.Env = env
	var ciphertext, encStderr bytes.Buffer
	encWithIdentity.Stdout, encWithIdentity.Stderr = &ciphertext, &encStderr
	if err := encWithIdentity.Run(); err != nil {
		t.Fatalf("age -e -i: %v\n%s", err, encStderr.String())
	}
	if _, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), attacker); err == nil {
		t.Fatal("injected attacker identity can decrypt")
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), id)
	if err != nil {
		t.Fatalf("intended identity cannot decrypt: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil || string(got) != plaintext {
		t.Fatalf("identity-based encryption roundtrip failed: %v", err)
	}
}
