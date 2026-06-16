# Plan — standalone verifier (next milestone)

Captured 2026-06-15 for review/presentation. This is the design + todo for the
next build after the freshness binding (now closed and demonstrated on
hardware, see [2026-06-16.md](2026-06-16.md)).

## Why

`run.sh` today produces **and** verifies evidence on the guest. A VM can't
meaningfully attest to itself — verification must run somewhere we trust. The
standalone verifier splits the one script into two roles. The freshness binding
we just finished is what makes that split sound: the nonce comes from the
verifier, so a matching quote proves the evidence is fresh and bound to a guest
key the verifier can encrypt to.

## Two roles

- **Attester** (on the CVM): gathers evidence into a bundle and sends it. Decides nothing.
- **Verifier** (on customer-controlled hardware, never the CVM): validates the bundle against pinned roots + policy, then releases the secret.

## Protocol (challenge-response)

1. Verifier generates a fresh **nonce**, sends it to the guest.
2. Guest makes an ephemeral X25519 keypair, reads the HCLA blob, takes an AK quote with qualifying data `H(domain ∥ nonce ∥ guest_pubkey ∥ ctx)`, assembles the **bundle**: HCLA blob, quote (msg/sig/pcrs), event log, guest pubkey, nonce echo, optional VCEK.
3. Guest sends the bundle to the verifier.
4. Verifier validates everything (checklist below).
5. On pass: verifier encrypts the LUKS key to the guest pubkey (X25519 ECDH → HKDF → AEAD, or `age`) and returns the ciphertext.
6. Guest decrypts in confidential memory and opens the encrypted data disk. The OS image stays non-secret; the key lives only in the verifier and guest RAM.

## Verifier checklist (brief step 9)

- AMD report signature valid; VCEK chains to **pinned** ARK/ASK (not fetched from Azure at verify time).
- TCB / security version acceptable; SNP debug bit disabled; VMPL / SNP policy acceptable.
- `report_data == H(runtime data)`; extract `HCLAkPub` from runtime claims.
- TPM quote valid under `HCLAkPub`; quote `extraData == binding hash` (verifier's nonce + guest pubkey).
- PCR digest + event log match the expected image; Secure Boot / TPM config acceptable.
- `vmUniqueId` / instance identity matches the expected VM.

## What's reused vs new

- **Reuse** (`lib/hcl.sh`, done): HCLA parse, `report_data` binding, `HCLAkPub`↔AK match, binding-hash.
- **New**: pinned-root chain validation, the policy engine, verifier-side nonce issuance, key-release crypto. Refactor: split `run.sh` Part 2 into an attester (emits bundle) + verifier (consumes it).

## Open decisions (to settle before building)

1. **v1 scope** — cryptographic + freshness + identity checks with a permissive/record-then-pin PCR policy, **or** the full policy engine up front?
2. **Language** — stay shell + openssl/tpm2-tools (consistent but brittle for event-log parsing + sealing), Python + `cryptography`, or Rust reusing `az-snp-vtpm` (brief's recommendation; most robust; new dep).
3. **Transport** — file-based bundle (mirrors the current `-v /out` flow, fully offline-demoable) or a real network challenge-response.

## Honest caveat for the talk

The hard part of a verifier is **not** the crypto (mostly done, easy to finish)
— it's **reference values**: deciding which HCL/UEFI/PCR measurements are
*acceptable*. Microsoft doesn't publish HCL reference values, so v1 nails
signature/freshness/identity and starts with a permissive or record-then-pin
PCR policy (brief "Risks #3"). "No Microsoft as authority" is achievable; "no
Microsoft in the measured TCB" is not.

## Suggested phasing (todo)

- [ ] **Phase 0 — decide** scope / language / transport (the three above).
- [ ] **Phase 1 — split roles**: refactor `run.sh` Part 2 into `attest.sh` (emit a bundle to `OUT_DIR`) and a `verify` entry point that consumes the bundle. File-based transport first.
- [ ] **Phase 2 — pinned roots**: ship ARK/ASK in the repo; verify VCEK → pinned roots instead of `snpguest fetch`.
- [ ] **Phase 3 — policy engine**: debug bit, TCB/security version, VMPL/SNP policy, `vmUniqueId`; PCR policy in record-then-pin mode first.
- [ ] **Phase 4 — key release**: verifier wraps a secret to the guest pubkey (X25519/`age`); guest unwraps and `cryptsetup open`s the data disk (brief step 10).
- [ ] **Phase 5 — tests**: extend the off-hardware self-test with a captured real bundle (replay-based), covering accept + each reject path.
