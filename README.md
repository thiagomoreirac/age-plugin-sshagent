# age-plugin-sshagent

[![CI](https://github.com/eszio/age-plugin-sshagent/actions/workflows/ci.yml/badge.svg)](https://github.com/eszio/age-plugin-sshagent/actions/workflows/ci.yml)

An [age](https://age-encryption.org) plugin that derives X25519 identities from deterministic ssh-agent signatures. Decryption keys are re-derived on demand by asking the agent to sign a fixed challenge — the ssh private key never leaves the agent and no new secret is stored on disk.

Two design properties make this practical:

1. **Recipients are native `age1...` X25519 recipients.** People encrypting to you use stock `age` with no plugin. Only you, the identity owner, need this binary — and only at decrypt time.

2. **The identity string (`AGE-PLUGIN-SSHAGENT-1...`) contains no secret material.** It encodes only the SHA-256 fingerprint of your ssh key and a random 16-byte salt. It does reveal which SSH key you use, and publishing it lets anyone with signing access to that key derive its decryption key. Keep a backup: the salt cannot be recovered from the SSH key or age recipient.

## How it works

```
agent_sign(challenge = "age-plugin-sshagent/v1/derive" || 0x00 || salt)
    → HKDF-SHA256(ikm=signature, salt=salt,
                  info="age-plugin-sshagent/v1/x25519" || 0x00 || fingerprint)
    → X25519 identity
```

The derivation is repeatable because Ed25519 signatures are deterministic (RFC 8032). Only `ssh-ed25519` keys are accepted for this reason — `sk-*` (FIDO) signatures include a counter and RSA agents may use randomized PSS padding, both of which break determinism and are therefore rejected.

The signature is verified against the public key before use. During `keygen`, the derivation runs twice and the results are compared, catching non-deterministic agents before anything is encrypted to the resulting recipient.

## Install

From a checkout whose source and revision you have reviewed:

```
go install .
```

This builds the checked-out source, rather than downloading another repository or an unreviewed `@latest` version. The installed binary must be on your `PATH` so that `age` can discover it as a plugin. Only trusted users should be able to modify that binary or its directory. Requires age v1.1.0 or later to decrypt.

## Usage

### Generate an identity

```
age-plugin-sshagent keygen [-k SELECTOR] [-o identity.txt]
```

With a single `ssh-ed25519` key loaded in the agent, no selector is needed. `-k` matches a substring of the key comment or its `SHA256:...` fingerprint. The identity is written to stdout, or to FILE with mode 0600 when -o is given (refusing to overwrite an existing file); the public key is also printed to stderr.

SSH key comments are quoted and control characters are escaped, so they cannot inject additional identity lines or terminal controls. Write and file-close errors cause a nonzero exit; do not encrypt to a new recipient until key generation succeeds and you have backed up the identity file. A failed write can leave a partial file: preserve any existing backup, remove only the failed output, and retry key generation.

Example output:

```
# created: 2026-06-12T10:00:00Z
# ssh key: SHA256:abcdef... "my-key"
# public key: age1examplerecipient...
AGE-PLUGIN-SSHAGENT-1...
Public key: age1examplerecipient...        # printed to stderr
```

### Encrypt (stock age, no plugin required)

```
age -e -r age1examplerecipient... file > file.age
```

### Decrypt

```
age -d -i identity.txt file.age
```

`age` discovers the plugin automatically from `PATH` and calls it to re-derive the decryption key.

### Re-derive a lost public key

```
age-plugin-sshagent recipient -i identity.txt
```

Useful when the `# public key:` comment line is gone. Requires the agent with the key loaded.

### List agent keys

```
age-plugin-sshagent list
```

Shows all keys currently in the agent and whether each is eligible.

## Security model

### Which key types are supported and why

Only `ssh-ed25519`. Ed25519 is deterministic by construction (RFC 8032): the same key and message always produce the same signature. `sk-*` (FIDO/hardware token) keys include a hardware counter in the signature, and RSA agents may use randomized PSS padding — both produce non-deterministic signatures that would yield a different decryption key on each invocation. These key types are detected and rejected explicitly.

### Agent access equals decryption access

Anyone with the identity payload and access to an agent that permits signing with the referenced key can request the same signature and re-derive your decryption key. This includes:

- **Processes running as your user** on the local machine.
- **Remote hosts when SSH agent forwarding is enabled** — forwarding exposes the signing capability to the remote host.

This exposure is broader than the risk in ordinary ssh authentication, where an attacker must be online at the exact moment of authentication. Here, one successful signature request yields the long-term decryption key permanently, allowing offline decryption of past and future files encrypted to that recipient. Removing the key from the agent, ending forwarding, or changing the SSH key's passphrase does not revoke a captured decryption key.

**Use a dedicated SSH key in a separate agent that is never forwarded.** Agent confirmation constraints, where supported, can reduce unauthorized signing, but cannot undo disclosure after a request is approved. A plugin-side confirmation cannot protect against clients that bypass the plugin and speak directly to the agent.

This risk is inherent to deriving an exportable key from a signature; it cannot be fixed without changing the design. If your requirement is that temporary agent access must never yield a reusable decryption key, do not use this plugin.

### Information exposure and process memory

The identity payload reveals an SSH-key fingerprint and salt. Generated identity files additionally include the key comment, creation timestamp, and age recipient. Key comments often contain identifying metadata; remove the comment lines before sharing if necessary. The `list` command intentionally displays agent key types, fingerprints, and comments.

The SSH private key stays in the agent, but the signature and derived age private key exist in the plugin's memory. The plugin does not deliberately write these secrets to disk, but does not lock or securely erase all copies of that memory. Process inspection, crash dumps, swap, or a compromised agent can expose decryption material. Protect the local account and `SSH_AUTH_SOCK`, and apply operating-system protections appropriate to your threat model.

### Honest framing

This scheme derives key material from a signature operation ("stunt cryptography"). The age author explicitly declined ssh-agent support upstream ([FiloSottile/age#7](https://github.com/FiloSottile/age/issues/7)) because the agent protocol can only sign — it cannot perform X25519 ECDH or RSA-OAEP decryption, which are the operations age is built on. This plugin exists for users who understand and accept that tradeoff in exchange for keeping zero secrets on disk. Prior art with the same approach: [sagecipher](https://github.com/p-sherratt/sagecipher), [hiera-eyaml-sshagent](https://github.com/asottile/hiera-eyaml-sshagent).

### Key rotation

A new ssh key produces different identities. After rotating your ssh key, re-encrypt any files encrypted to the old recipient and distribute the new recipient. Old identities require the old key or a previously captured derived key. Re-encryption cannot revoke access to old ciphertext copies.

### Agent lifecycle

The agent must be running and have the key loaded (`SSH_AUTH_SOCK` must point to it). Managing the agent — starting it, adding keys via `ssh-add`, unlocking passphrase-protected keys — is the user's responsibility, the same contract as ssh itself.

## FAQ

**Why not just keep an unencrypted age identity file?**

Threat models differ. An unencrypted age private-key file is readable by anything that can read that file: backup systems, cloud sync, or anyone with access to a snapshot containing it. This plugin's identity file contains no private key, which can help when it is backed up or synced elsewhere. During use, however, decryption material exists in both the agent and plugin processes; see the agent-access and process-memory limitations above.

**Why ed25519 only?**

Determinism. See [Which key types are supported](#which-key-types-are-supported-and-why) above.

**Can I use this with a passphrase-protected ssh key?**

Yes — that is one of the main use cases. Load the key once via `ssh-add` (or your OS keychain) and the agent holds the decrypted key in memory. The plugin requests a signature from the agent; it never sees or handles your passphrase.

## License

BSD-3-Clause, the same license as age. See [LICENSE](LICENSE).

The `internal/bech32` package is vendored from [filippo.io/age](https://github.com/FiloSottile/age) and is MIT-licensed; its original license header is preserved in the source file.
