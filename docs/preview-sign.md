# Experimental single-passkey wallet unlocking and signing

This `previewSign-single-key` branch uses one WebAuthn credential for login, PRF wallet unlocking and previewSign v4 / ARKG-P256 signing. The PRF-derived encryption key, WebAuthn authentication key and ARKG signing seed remain distinct cryptographic values. Credential contents, history, software keys and issuance sessions remain encrypted.

## Set up and try

1. Use this branch in the frontend and backend. Hardware signing defaults to enabled in both applications. Keep `PREVIEW_SIGN_ENABLED=true` in both environments before registering a passkey (`false` is an explicit software-only opt-out). Both PRF and previewSign v4 must work together in the selected client and authenticator. Missing previewSign output is an explicit error when enabled; disabling the flag retains ordinary PRF/software operation.
2. Use a **fresh backend database**, such as `wallet_single_key`. The backend `.env` in this worktree selects that name. Create it and run `yarn init-db` from the parent project. The parent README has the exact commands. Do not run this branch's modified signing migration against the original `wallet` database. Existing separate signing registrations are not converted.
3. Create a new test wallet using a compatible security-key passkey, or add a compatible passkey in Settings. That one `navigator.credentials.create()` requests both `prf` and `previewSign.generateKey`. Normal wallet initialization evaluates PRF and saves the encrypted container. The server validates and retains the seed attestation as provisional data on the same WebAuthn credential while setup completes.
4. Registration automatically performs a `get()` test-signature ceremony using that passkey. Follow the authenticator prompt; there is no separate enable action or second WebAuthn credential. The server saves the ARKG registration only after verifying the enclosing assertion and a signature under a server-derived public key. The encrypted wallet records the public seed and selects it for new holder keys before signup succeeds. Settings shows the active signing passkey. Adding another passkey also verifies and saves its seed, retaining the existing active seed if one is already selected.
5. Issue a **new** SD-JWT or mdoc credential, then present it. Watch `/user/session/preview-sign/sign-begin` and `sign-finish` in DevTools. Signing prompts run sequentially for proof batches. The same credential ID is used for PRF unlocking and previewSign.
6. Cancel a signing prompt: the hardware operation must fail. Retry and approve to complete it. Existing ARKG-bound credentials always require their original shared passkey and online registration.

Signing setup is automatic during signup and added-passkey registration. If the test is canceled after the account/passkey is saved, sign in using that same passkey to retry; provisional metadata is retained. An online login retries setup if that passkey has no saved seed or the wallet has no active seed, before completing login. An existing active holder seed is retained when recovering another passkey. If proof succeeds but encrypted-state upload fails, the next login retrieves the already verified seed and repairs the wallet copy without another create ceremony. Existing software-bound credentials retain their original holder keys. Passkeys registered while previewSign was disabled have no seed to activate: create a fresh test wallet, or add a newly registered compatible passkey from an already open wallet. A plain-text/HTML backend error preserves its HTTP status instead of producing a JSON parsing exception; an unavailable previewSign endpoint reports the backend configuration problem.

## Storage and lifecycle

- `webauthn_credential` stores the shared credential ID, public key, transports, authoritative signature counter and provisional `pendingSigningAttestation`.
- `signing_credential` stores only seed metadata and a unique foreign-key reference to that WebAuthn record. It has no duplicate authentication key or counter. Deleting a shared passkey cascades to its signing registration.
- The encrypted wallet state's `arkgSeeds` contains the same base64url credential ID as the selected PRF record. ARKG holder records in `keypairs` contain a public JWK, seed ID, ticket and context, with no holder private JWK.
- Removing an active shared passkey deselects it for future issuance. Historical seed and holder records remain identifiable; credentials already bound to that removed registration cannot sign through it. Keep the original shared passkey and its registration for those credentials.
- The public seed and tickets cannot replace a lost hardware signer. Restoring an encrypted backup alone does not recreate the backend WebAuthn/signing registration.

## Verification

Login, enrollment proof and normal previewSign assertions lock and update the **same** `webauthn_credential` row. Counter changes are committed only after all required checks pass. Enrollment proof tokens are scoped to the account and RP, expire after five minutes, and use an atomically consumed challenge. Ownership, credential ID, RP ID, origin and UV are checked. Ordinary login rejects signing-purpose challenges. The frontend additionally verifies every holder signature against its derived public key and exact signing input.

Packed ES256/ESP256 seed attestations are checked when present. `fmt: none` is accepted only with the mandatory proof of signing-key possession. Neither path establishes manufacturer provenance through an attestation trust store. Public derivation retains the v4 prototype identifiers (`-65539`, `-65537`, `-65700`); firmware and client compatibility must be tested together.

With hardware signing enabled, new holder-key generation requires an active seed and fails instead of falling back to a software key. The wallet-state schema is version 4. PRF → HKDF → ECDH → AES-KW unlocking and JWE encryption remain. Existing software holder records and protocol DPoP keys remain supported. Old clients cannot read schema-4 events.

## Automated checks

```sh
yarn typecheck
yarn lint
yarn test
yarn build
```

The backend's `yarn test:preview-sign` checks public derivation vectors, registration validation, proof signatures/tokens and shared-credential assertions. `yarn test:single-key:integration` additionally exercises real HTTP routes and MariaDB; it requires an empty disposable database whose name begins with `preview_sign_single_key_test`. See the backend README for its setup. Simulated authenticators use generated keys or published test seed material. A physical device/client test remains necessary to confirm combined extension support.

- [previewSign v4](https://yubicolabs.github.io/webauthn-sign-extension/4/)
- [ARKG specification and test vectors](https://yubico.github.io/arkg-rfc/priv-cons-pub-seed-secrecy/draft-bradleylundberg-cfrg-arkg.html)
