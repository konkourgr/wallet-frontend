import { afterEach, describe, expect, it, vi } from 'vitest';
import { Decoder } from 'cbor-x';
import { p256 } from '@noble/curves/nist.js';
import * as jose from 'jose';
import { fromBase64Url, toBase64Url } from '@/util';
import {
	createPreviewSignClient,
	enrollArkgSeed,
	getSigningAttestation,
	combinedRegistrationExtensions,
} from './previewSign';
import { signWalletJwt, signWithWalletKey } from './walletSigning';
import type { ArkgSeed, ArkgSigningKey } from './previewSignTypes';
import vectors from './arkg.vectors.json';

const testConfig = vi.hoisted(() => ({ PREVIEW_SIGN_ENABLED: true, WEBAUTHN_RPID: 'wallet.example.org' }));
vi.mock('@/config', () => testConfig);
const hex = (value: string) => Uint8Array.from(value.match(/../g)!.map((byte) => parseInt(byte, 16)));
const rawKey = hex(vectors[0].pk_prime);
const publicKey = { kty: 'EC', crv: 'P-256', x: toBase64Url(rawKey.slice(1, 33)), y: toBase64Url(rawKey.slice(33)) };
const seed: ArkgSeed = {
	id: 'seed-1',
	credentialId: 'Y3JlZA',
	keyHandle: 'aGFuZGxl',
	publicSeed: '',
	algorithm: -65539,
};
const key: ArkgSigningKey = {
	type: 'arkg',
	kid: 'holder',
	alg: 'ES256',
	publicKey,
	seedId: seed.id,
	ticket: toBase64Url(hex(vectors[0].kh)),
	context: toBase64Url(new TextEncoder().encode(vectors[0].ctx)),
};
// Corresponding derived private scalar from published Appendix A.1, test data only.
const testPrivate = '775d7fe9a6dfba43ce671cb38afca3d272c4d14aff97bd67559eb500a092e5e7'.padStart(64, '0');

afterEach(() => {
	testConfig.PREVIEW_SIGN_ENABLED = true;
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

function harness(options: { missingOutput?: boolean; wrongSignature?: boolean; rejectedAssertion?: boolean } = {}) {
	let signature: Uint8Array = new Uint8Array();
	let request: PublicKeyCredentialRequestOptions;
	const get = vi.fn(async (input: CredentialRequestOptions) => {
		request = input.publicKey!;
		const signInput = (request.extensions as any).previewSign.signByCredential[seed.credentialId];
		signature = p256.sign(new Uint8Array(signInput.tbs), hex(testPrivate), { prehash: false }).toBytes('der');
		if (options.wrongSignature) signature[signature.length - 1] ^= 1;
		return {
			id: seed.credentialId,
			rawId: fromBase64Url(seed.credentialId).buffer,
			type: 'public-key',
			response: {
				clientDataJSON: new ArrayBuffer(0),
				authenticatorData: new ArrayBuffer(0),
				signature: new ArrayBuffer(0),
				userHandle: null,
			},
			getClientExtensionResults: () => (options.missingOutput ? {} : { previewSign: { signature: signature.buffer } }),
		};
	});
	vi.stubGlobal('AuthenticatorAttestationResponse', class {});
	vi.stubGlobal('navigator', { credentials: { get } });
	const post = vi.fn(async (path: string) => {
		if (path.endsWith('sign-begin')) return { data: { challengeId: 'one-time', challenge: new Uint8Array(32) } };
		if (options.rejectedAssertion) throw new Error('assertion verification failed');
		return { data: { signature: toBase64Url(signature) } };
	});
	return { client: createPreviewSignClient(post), post, get, request: () => request! };
}

describe('previewSign v4 signing', () => {
	it('prehashes the exact JWS input, sends integer CBOR arguments, verifies the assertion, and returns a valid ES256 JWT', async () => {
		const h = harness();
		const jwt = await signWalletJwt(
			{ nonce: 'nonce', aud: 'issuer' },
			{ alg: 'ES256', typ: 'openid4vci-proof+jwt' },
			key,
			[seed],
			h.client,
		);
		const verified = await jose.jwtVerify(jwt, await jose.importJWK(publicKey, 'ES256'), { audience: 'issuer' });
		expect(verified.payload.nonce).toBe('nonce');
		const input = jwt.split('.').slice(0, 2).join('.');
		const expectedDigest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
		const request = h.request();
		expect(request.userVerification).toBe('required');
		expect(request.allowCredentials?.[0].id).toEqual(fromBase64Url(seed.credentialId));
		const params = (request.extensions as any).previewSign.signByCredential[seed.credentialId];
		expect(new Uint8Array(params.tbs)).toEqual(new Uint8Array(expectedDigest));
		const args = new Decoder({ mapsAsObjects: false }).decode(params.additionalArgs);
		expect(args.get(3)).toBe(-65539);
		expect(Uint8Array.from(args.get(-1))).toEqual(fromBase64Url(key.ticket));
		expect(Uint8Array.from(args.get(-2))).toEqual(fromBase64Url(key.context));
		expect(h.post.mock.calls.map(([path]) => path)).toEqual([
			'/user/session/preview-sign/sign-begin',
			'/user/session/preview-sign/sign-finish',
		]);
		expect(fromBase64Url(jwt.split('.')[2])).toHaveLength(64);
	});

	it.each([
		[{ missingOutput: true }, 'did not return'],
		[{ wrongSignature: true }, 'does not match'],
		[{ rejectedAssertion: true }, 'assertion verification failed'],
	] as const)('rejects incomplete or invalid hardware operations: %j', async (options, message) => {
		await expect(harness(options).client.sign(seed, key, new TextEncoder().encode('input'))).rejects.toThrow(message);
	});

	it('rejects a missing seed or unavailable hardware without falling back to a software key', async () => {
		await expect(signWithWalletKey(key, [], new Uint8Array(), harness().client)).rejects.toThrow('seed not found');
		await expect(signWithWalletKey(key, [seed], new Uint8Array())).rejects.toThrow('unavailable');
	});

	it('preserves legacy software signing', async () => {
		const { privateKey, publicKey: softwarePublicKey } = await jose.generateKeyPair('ES256', { extractable: true });
		const software = {
			kid: 'legacy',
			alg: 'ES256',
			publicKey: await jose.exportJWK(softwarePublicKey),
			privateKey: await jose.exportJWK(privateKey),
		};
		const jwt = await signWalletJwt({ nonce: 'old' }, { alg: 'ES256', typ: 'kb+jwt' }, software, []);
		expect((await jose.jwtVerify(jwt, softwarePublicKey)).payload.nonce).toBe('old');
	});

	it('rejects a passkey registration that omits previewSign', () => {
		expect(() =>
			getSigningAttestation({
				getClientExtensionResults: () => ({ prf: { enabled: true } }),
			} as unknown as PublicKeyCredential),
		).toThrow('both PRF and previewSign');
	});
	it('requests PRF and previewSign on one credential without losing other extensions', () => {
		const prf = { eval: { first: new Uint8Array(32) } };
		const extensions = combinedRegistrationExtensions({ prf, credProps: true } as AuthenticationExtensionsClientInputs);
		expect(extensions).toMatchObject({ prf, credProps: true, previewSign: { generateKey: { algorithms: [-65539] } } });
	});

	it.each([
		{
			error: 'WebAuthn attestation could not be verified.',
			reason: 'Unsupported certificate algorithm',
			code: 'PREVIEW_SIGN_WEBAUTHN_FAILED',
		},
		{ error: 'Apply the previewSign database migration.', code: 'PREVIEW_SIGN_MIGRATION_REQUIRED' },
	])('shows actionable enrollment errors from the server: $code', async (failure) => {
		const post = vi.fn(async (path: string) => {
			throw { response: { data: failure } };
		});
		await expect(enrollArkgSeed(post, seed.credentialId)).rejects.toThrow(failure.code);
		await expect(enrollArkgSeed(post, seed.credentialId)).rejects.toThrow(failure.reason ?? failure.error);
	});
});

async function enrollmentHarness(corrupt = false) {
	vi.spyOn(await import('./arkg'), 'decodeArkgPublicSeed').mockReturnValue({ blinding: rawKey, kem: rawKey });
	const h = harness({ wrongSignature: corrupt });
	class RegistrationResponse {
		clientDataJSON = new ArrayBuffer(1);
		attestationObject = new ArrayBuffer(1);
		getTransports() {
			return ['usb'];
		}
	}
	vi.stubGlobal('AuthenticatorAttestationResponse', RegistrationResponse);
	const create = vi.fn(async () => ({
		id: seed.credentialId,
		rawId: fromBase64Url(seed.credentialId).buffer,
		type: 'public-key',
		response: new RegistrationResponse(),
		getClientExtensionResults: () => ({
			previewSign: {
				generatedKey: { algorithm: -65539, publicKey: new ArrayBuffer(1), attestationObject: new ArrayBuffer(1) },
			},
		}),
	}));
	vi.stubGlobal('navigator', { credentials: { create, get: h.get } });
	const registered = { ...seed, attestation: 'none' };
	const challenge = new Uint8Array(32).fill(7);
	const proofData = new TextEncoder().encode('server chosen enrollment challenge');
	const post = vi.fn(async (path: string, _body: object) => {
		if (path.endsWith('register-begin'))
			return {
				data: { seed: registered, registrationToken: 'pending-token', proof: { key, data: proofData, challenge } },
			};
		if (path.endsWith('register-complete')) return { data: registered };
		throw new Error('Unexpected endpoint');
	});
	return { ...h, post, registered, challenge, create };
}

describe('enrollment signing proof', () => {
	it('explains disabled or missing backend routes instead of exposing a JSON parser error', async () => {
		const post = vi.fn(async () => {
			throw { response: { status: 404, data: 'Not Found' } };
		});
		await expect(enrollArkgSeed(post, seed.credentialId)).rejects.toThrow('Enable PREVIEW_SIGN_ENABLED');
	});
	it('completes none enrollment only after a valid test signature', async () => {
		const h = await enrollmentHarness();
		await expect(enrollArkgSeed(h.post, seed.credentialId)).resolves.toEqual(h.registered);
		expect(h.post.mock.calls.map(([path]) => path)).toEqual([
			'/user/session/preview-sign/register-begin',
			'/user/session/preview-sign/register-complete',
		]);
		expect(h.post.mock.calls[1][1]).toMatchObject({
			registrationToken: 'pending-token',
			credential: { id: seed.credentialId },
		});
		expect(h.request().challenge).toBe(h.challenge);
		expect(h.create).not.toHaveBeenCalled();
		expect(h.get).toHaveBeenCalledTimes(1);
	});
	it('does not complete enrollment when the test signature is invalid', async () => {
		const h = await enrollmentHarness(true);
		await expect(enrollArkgSeed(h.post, seed.credentialId)).rejects.toThrow('does not match');
		expect(h.post).toHaveBeenCalledTimes(1);
		expect(h.create).not.toHaveBeenCalled();
		expect(h.get).toHaveBeenCalledTimes(1);
	});
});

it('restores a verified seed after an encrypted-state upload failed without another registration', async () => {
	const h = await enrollmentHarness();
	const post = vi.fn(async () => ({ data: { alreadyEnrolled: true, seed: h.registered } }));
	await expect(enrollArkgSeed(post, seed.credentialId)).resolves.toEqual(h.registered);
	expect(h.get).not.toHaveBeenCalled();
	expect(h.create).not.toHaveBeenCalled();
});
it('rejects a server response referring to a different unlocking passkey', async () => {
	const h = await enrollmentHarness();
	await expect(enrollArkgSeed(h.post, 'different-passkey')).rejects.toThrow('different PRF passkey');
	expect(h.get).not.toHaveBeenCalled();
});

it('keeps ordinary PRF registration available when the hardware flag is disabled', () => {
	testConfig.PREVIEW_SIGN_ENABLED = false;
	const prf = { eval: { first: new Uint8Array(32) } };
	expect(combinedRegistrationExtensions({ prf } as AuthenticationExtensionsClientInputs)).toEqual({ prf });
	const getClientExtensionResults = vi.fn();
	expect(getSigningAttestation({ getClientExtensionResults } as unknown as PublicKeyCredential)).toBeUndefined();
	expect(getClientExtensionResults).not.toHaveBeenCalled();
});
