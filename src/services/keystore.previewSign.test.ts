import { describe, expect, it, vi } from 'vitest';
import * as jose from 'jose';
import { Encoder } from 'cbor-x';
import { p256 } from '@noble/curves/nist.js';
import { hash_to_field } from '@noble/curves/abstract/hash-to-curve.js';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { fromBase64Url, toBase64Url } from '@/util';
import * as keystore from './keystore';
import { addConfigureArkgEvent, foldState } from './WalletStateSchema';
import type { ArkgSeed } from './previewSignTypes';
import type { PreviewSignClient } from './previewSign';
import { activateSharedPasskeySigning } from './sharedPasskeyRegistration';
import vectors from './arkg.vectors.json';

vi.mock('@/config', () => ({ PREVIEW_SIGN_ENABLED: true }));
const text = (value: string) => new TextEncoder().encode(value);
const hex = (value: string) => Uint8Array.from(value.match(/../g)!.map((byte) => parseInt(byte, 16)));
const cose = new Encoder({ useRecords: false, mapsAsObjects: false, variableMapSize: true, tagUint8Array: false });
const point = (value: string) =>
	new Map<number, unknown>([
		[1, 2],
		[-1, 1],
		[-2, hex(value).slice(1, 33)],
		[-3, hex(value).slice(33)],
	]);
const seed: ArkgSeed = {
	id: 'test-seed',
	credentialId: 'Y3JlZA',
	keyHandle: 'aGFuZGxl',
	algorithm: -65539,
	publicSeed: toBase64Url(
		cose.encode(
			new Map<number, unknown>([
				[1, -65537],
				[3, -65700],
				[-1, point(vectors[0].pk_bl)],
				[-2, point(vectors[0].pk_kem)],
				[-3, -9],
			]),
		),
	),
};

/** Test-only delegating party, using the published private seed. This independently
 * decapsulates tickets instead of generating private holder keys in the wallet.
 */
function testAuthenticator(): PreviewSignClient {
	return {
		sign: vi.fn(async (_seed, key, data) => {
			const context = fromBase64Url(key.context);
			const encodedContext = Uint8Array.from([context.length, ...context]);
			const ctxKem = Uint8Array.from([...text('ARKG-Derive-Key-KEM.'), ...encodedContext]);
			const shared = p256
				.getSharedSecret(
					BigInt('0x74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5'),
					fromBase64Url(key.ticket).slice(16),
					false,
				)
				.slice(1, 33);
			const ikm = hkdf(
				sha256,
				shared,
				undefined,
				Uint8Array.from([...text('ARKG-KEM-HMAC-shared.ARKG-ECDH.ARKG-P256'), ...ctxKem]),
				32,
			);
			const tau = hash_to_field(ikm, 1, {
				DST: Uint8Array.from([...text('ARKG-BL-EC.ARKG-P256ARKG-Derive-Key-BL.'), ...encodedContext]),
				p: p256.CURVE.n,
				m: 1,
				k: 128,
				expand: 'xmd',
				hash: sha256,
			})[0][0];
			const secret =
				(BigInt('0xd959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455') + tau) % p256.CURVE.n;
			return p256.sign(sha256(data), secret, { prehash: false }).toBytes('compact');
		}),
	};
}

async function unconfiguredContainer(): Promise<keystore.OpenedContainer> {
	const credential = {
		id: seed.credentialId,
		rawId: fromBase64Url(seed.credentialId).buffer,
		response: { getTransports: () => [] },
		getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).fill(7).buffer } } }),
	} as unknown as PublicKeyCredential;
	const { mainKey, keyInfo } = await keystore.initPrf(credential, new Uint8Array(32), async () => false);
	const initialized = await keystore.init(mainKey, keyInfo);
	return [keystore.assertAsymmetricEncryptedContainer(initialized.privateData), initialized.mainKey];
}

async function initializedContainer(): Promise<keystore.OpenedContainer> {
	const [privateData, mainKey] = await unconfiguredContainer();
	const [data] = await keystore.openPrivateData(mainKey, privateData);
	return (await keystore.updateWalletState([privateData, mainKey], await addConfigureArkgEvent(data, seed.id, seed)))
		.newContainer;
}

describe('hardware holder keys in the encrypted wallet', () => {
	it('automatically activates a verified seed, preserves PRF unlocking, and derives hardware holder keys', async () => {
		const original = await unconfiguredContainer();
		const post = vi.fn(async () => ({ data: { alreadyEnrolled: true, seed } }));
		const configured = await activateSharedPasskeySigning(original, seed.credentialId, post);
		const [, , state] = await keystore.openPrivateData(configured[1], configured[0]);
		expect(state.arkgSeeds).toEqual([seed]);
		expect(state.activeArkgSeedId).toBe(seed.id);
		const credential = {
			id: seed.credentialId,
			rawId: fromBase64Url(seed.credentialId).buffer,
			getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).fill(7).buffer } } }),
		} as unknown as PublicKeyCredential;
		const [unlocked] = await keystore.unlockPrf(configured[0], credential, async () => false);
		expect((await keystore.openPrivateData(unlocked.mainKey, unlocked.privateData))[2].activeArkgSeedId).toBe(seed.id);
		const [{ keypairs }] = await keystore.generateKeypairs(configured, undefined);
		expect(keypairs[0].type).toBe('arkg');
		expect(keypairs[0]).not.toHaveProperty('privateKey');
		expect(await activateSharedPasskeySigning(configured, seed.credentialId, post)).toBe(configured);
		expect(post).toHaveBeenCalledTimes(1);
	});
	it('fails setup without changing the encrypted wallet when the backend is disabled', async () => {
		const original = await unconfiguredContainer();
		const post = vi.fn(async () => {
			throw { response: { status: 404, data: 'Not Found' } };
		});
		await expect(activateSharedPasskeySigning(original, seed.credentialId, post)).rejects.toMatchObject({
			errorId: 'hardware_signing_setup_failed',
		});
		const state = (await keystore.openPrivateData(original[1], original[0]))[2];
		expect(state.arkgSeeds).toEqual([]);
		expect(state.activeArkgSeedId).toBeNull();
	});
	it('recovers an added passkey after interrupted setup while retaining the active holder seed', async () => {
		const initial = await initializedContainer();
		const credentialId = toBase64Url(text('second shared passkey'));
		const secondSeed = { ...seed, id: 'second-seed', credentialId };
		const withAddedPasskey: keystore.OpenedContainer = [
			{
				...initial[0],
				prfKeys: [...initial[0].prfKeys, { ...initial[0].prfKeys[0], credentialId: fromBase64Url(credentialId) }],
			},
			initial[1],
		];
		const post = vi.fn(async () => ({ data: { alreadyEnrolled: true, seed: secondSeed } }));
		const configured = await activateSharedPasskeySigning(withAddedPasskey, credentialId, post);
		const state = (await keystore.openPrivateData(configured[1], configured[0]))[2];
		expect(state.activeArkgSeedId).toBe(seed.id);
		expect(state.arkgSeeds).toEqual([seed, secondSeed]);
		expect(post).toHaveBeenCalledTimes(1);
	});
	it('issues a batch, restores the keys from encrypted storage, and signs an SD-JWT presentation', async () => {
		const initial = await initializedContainer();
		const hardware = testAuthenticator();
		const [{ proof_jwts }, updated] = await keystore.generateOpenid4vciProofs(
			initial,
			undefined,
			'issuance-nonce',
			'issuer',
			'wallet',
			2,
			hardware,
		);
		const opened = await keystore.openPrivateData(updated[1], updated[0]);
		const state = opened[2];
		expect(state.arkgSeeds).toEqual([seed]);
		expect(state.keypairs).toHaveLength(2);
		expect(updated[0].prfKeys).toHaveLength(1);
		expect(toBase64Url(updated[0].prfKeys[0].credentialId)).toBe(seed.credentialId);
		for (const [index, stored] of state.keypairs.entries()) {
			expect(stored.keypair.type).toBe('arkg');
			expect(stored.keypair).not.toHaveProperty('privateKey');
			const publicKey = await jose.importJWK(stored.keypair.publicKey, 'ES256');
			const verified = await jose.jwtVerify(proof_jwts[index], publicKey, { audience: 'issuer' });
			expect(verified.payload.nonce).toBe('issuance-nonce');
			expect(await jose.calculateJwkThumbprint(stored.keypair.publicKey)).toBe(stored.kid);
		}
		const holder = state.keypairs[0].keypair;
		const issuer = await jose.generateKeyPair('ES256');
		const sdJwt =
			(await new jose.SignJWT({ cnf: { jwk: holder.publicKey } })
				.setProtectedHeader({ alg: 'ES256' })
				.sign(issuer.privateKey)) + '~';
		const { vpjwt } = await keystore.signJwtPresentation(
			opened,
			'presentation-nonce',
			'verifier',
			[sdJwt],
			undefined,
			hardware,
		);
		const kbJwt = vpjwt.slice(sdJwt.length);
		const verified = await jose.jwtVerify(kbJwt, await jose.importJWK(holder.publicKey, 'ES256'), {
			audience: 'verifier',
		});
		expect(verified.payload.nonce).toBe('presentation-nonce');
		expect(verified.payload.sd_hash).toBe(toBase64Url(await crypto.subtle.digest('SHA-256', text(sdJwt))));
		expect(hardware.sign).toHaveBeenCalledTimes(3);
	});

	it('rejects new issuance with no active seed instead of falling back to software', async () => {
		const [{ keypairs: hardwareKeys }, withHardware] = await keystore.generateKeypairs(
			await initializedContainer(),
			'p256-pub',
		);
		expect(hardwareKeys[0].type).toBe('arkg');
		expect(hardwareKeys[0].did).toMatch(/^did:key:/);
		const [data] = await keystore.openPrivateData(withHardware[1], withHardware[0]);
		const switched = (await keystore.updateWalletState(withHardware, await addConfigureArkgEvent(data, null)))
			.newContainer;
		await expect(keystore.generateKeypairs(switched, undefined)).rejects.toThrow('Complete hardware signing setup');
		const [stored] = await keystore.openPrivateData(switched[1], switched[0]);
		expect(foldState(stored).keypairs.some((entry) => entry.keypair.type === 'arkg')).toBe(true);
	});
	it('deselects signing when its shared unlocking passkey is removed', async () => {
		const initial = await initializedContainer();
		const [{ keypairs }, withHolder] = await keystore.generateKeypairs(initial, undefined);
		const otherId = new TextEncoder().encode('second passkey');
		const original: keystore.OpenedContainer = [
			{ ...withHolder[0], prfKeys: [...withHolder[0].prfKeys, { ...withHolder[0].prfKeys[0], credentialId: otherId }] },
			withHolder[1],
		];
		const removedOther = await keystore.deleteSharedPasskey(original, otherId);
		expect((await keystore.openPrivateData(removedOther[1], removedOther[0]))[2].activeArkgSeedId).toBe(seed.id);
		const removedShared = await keystore.deleteSharedPasskey(original, fromBase64Url(seed.credentialId));
		const state = (await keystore.openPrivateData(removedShared[1], removedShared[0]))[2];
		expect(state.activeArkgSeedId).toBeNull();
		expect(state.arkgSeeds).toEqual([seed]);
		expect(state.keypairs[0].keypair).toEqual(keypairs[0]);
		expect(removedShared[0].prfKeys).toHaveLength(1);
		expect(toBase64Url(removedShared[0].prfKeys[0].credentialId)).toBe(toBase64Url(otherId));
	});
});
