import { Encoder } from 'cbor-x';
import { p256 } from '@noble/curves/nist.js';
import { fromBase64Url, toBase64Url } from '@/util';
import { WEBAUTHN_RPID, PREVIEW_SIGN_ENABLED } from '@/config';
import { decodeArkgPublicSeed } from './arkg';
import { PREVIEW_SIGN_ALGORITHM, type ArkgSeed, type ArkgSigningKey } from './previewSignTypes';

type Post = (path: string, body: object) => Promise<{ data: any }>;
const cbor = new Encoder({ useRecords: false, mapsAsObjects: false, tagUint8Array: false, variableMapSize: true });
type PreviewOutput = {
	generatedKey?: { keyHandle: ArrayBuffer; publicKey: ArrayBuffer; algorithm: number; attestationObject: ArrayBuffer };
	signature?: ArrayBuffer;
};
export type PreviewSignClient = {
	sign(seed: ArkgSeed, key: ArkgSigningKey, data: Uint8Array): Promise<Uint8Array>;
};

function requireEnabled() {
	if (!PREVIEW_SIGN_ENABLED) throw new Error('Experimental hardware signing is disabled');
}

export function serializeWebauthnCredential(credential: PublicKeyCredential) {
	const response = credential.response;
	return {
		type: credential.type,
		id: credential.id,
		rawId: credential.rawId,
		response:
			response instanceof AuthenticatorAttestationResponse
				? {
						clientDataJSON: response.clientDataJSON,
						attestationObject: response.attestationObject,
						transports: response.getTransports(),
					}
				: {
						clientDataJSON: response.clientDataJSON,
						authenticatorData: (response as AuthenticatorAssertionResponse).authenticatorData,
						signature: (response as AuthenticatorAssertionResponse).signature,
						userHandle: (response as AuthenticatorAssertionResponse).userHandle,
					},
	};
}

/** Add both extensions to a single new login/PRF credential. */
export function combinedRegistrationExtensions(
	existing: AuthenticationExtensionsClientInputs = {},
): AuthenticationExtensionsClientInputs {
	return {
		...existing,
		...(PREVIEW_SIGN_ENABLED ? { previewSign: { generateKey: { algorithms: [PREVIEW_SIGN_ALGORITHM] } } } : {}),
	} as AuthenticationExtensionsClientInputs;
}

export function getSigningAttestation(credential: PublicKeyCredential): ArrayBuffer | undefined {
	if (!PREVIEW_SIGN_ENABLED) return undefined;
	const output = (credential.getClientExtensionResults() as { previewSign?: PreviewOutput }).previewSign;
	if (!output?.generatedKey || output.generatedKey.algorithm !== PREVIEW_SIGN_ALGORITHM) {
		throw new Error('This passkey must support both PRF and previewSign v4. Use a compatible security key and client.');
	}
	decodeArkgPublicSeed(new Uint8Array(output.generatedKey.publicKey));
	return output.generatedKey.attestationObject;
}

/** Activate the seed created with an existing PRF passkey; never calls create(). */
export async function enrollArkgSeed(post: Post, credentialId: string): Promise<ArkgSeed> {
	requireEnabled();
	const { data: pending } = await enrollmentPost(post, '/user/session/preview-sign/register-begin', { credentialId });
	const seed = pending.seed as ArkgSeed;
	if (seed.credentialId !== credentialId) throw new Error('Enrollment returned a different PRF passkey');
	decodeArkgPublicSeed(fromBase64Url(seed.publicSeed));
	// A completed registration can be restored after a failed encrypted-state upload.
	if (pending.alreadyEnrolled) return seed;
	const proofKey = pending.proof.key as ArkgSigningKey;
	const proofData = pending.proof.data as Uint8Array;
	const signed = await requestPreviewSignature(seed, proofKey, proofData, pending.proof.challenge);
	await verifyHardwareSignature(signed.signature, proofKey, proofData);
	const { data: registered } = await enrollmentPost(post, '/user/session/preview-sign/register-complete', {
		registrationToken: pending.registrationToken,
		credential: serializeWebauthnCredential(signed.assertion),
	});
	if (registered.credentialId !== credentialId || registered.id !== seed.id)
		throw new Error('Enrollment returned a different PRF passkey');
	return registered as ArkgSeed;
}

async function enrollmentPost(post: Post, path: string, body: object) {
	try {
		return await post(path, body);
	} catch (error) {
		const failure = (error as { response?: { data?: { error?: string; reason?: string; code?: string } } })?.response
			?.data;
		if ((error as { response?: { status?: number } })?.response?.status === 404)
			throw new Error(
				'The backend previewSign endpoint is unavailable. Enable PREVIEW_SIGN_ENABLED in the matching backend and restart it',
			);
		if (
			typeof failure?.error === 'string' &&
			typeof failure.code === 'string' &&
			failure.code.startsWith('PREVIEW_SIGN_')
		)
			throw new Error([failure.error, failure.reason, `(${failure.code})`].filter(Boolean).join(' '));
		throw error;
	}
}

async function requestPreviewSignature(seed: ArkgSeed, key: ArkgSigningKey, data: Uint8Array, challenge: BufferSource) {
	requireEnabled();
	if (seed.algorithm !== PREVIEW_SIGN_ALGORITHM || key.seedId !== seed.id) throw new Error('Invalid ARKG seed');
	const ticket = fromBase64Url(key.ticket),
		context = fromBase64Url(key.context);
	if (ticket.length !== 81 || context.length > 64) throw new Error('Invalid ARKG ticket or context');
	const digest = await crypto.subtle.digest('SHA-256', Uint8Array.from(data));
	const additionalArgs = cbor.encode(
		new Map<number, unknown>([
			[3, PREVIEW_SIGN_ALGORITHM],
			[-1, ticket],
			[-2, context],
		]),
	);
	const assertion = (await navigator.credentials.get({
		publicKey: {
			rpId: WEBAUTHN_RPID,
			challenge,
			allowCredentials: [{ type: 'public-key', id: fromBase64Url(seed.credentialId), transports: seed.transports }],
			userVerification: 'required',
			extensions: {
				previewSign: {
					signByCredential: {
						[seed.credentialId]: { keyHandle: fromBase64Url(seed.keyHandle), tbs: digest, additionalArgs },
					},
				},
			} as AuthenticationExtensionsClientInputs,
		},
	})) as PublicKeyCredential | null;
	if (!assertion || assertion.id !== seed.credentialId)
		throw new Error('Hardware signing was canceled or used a different key');
	const output = (assertion.getClientExtensionResults() as { previewSign?: PreviewOutput }).previewSign;
	if (!output?.signature) throw new Error('The browser or security key did not return a previewSign signature');
	return { assertion, signature: new Uint8Array(output.signature) };
}

async function verifyHardwareSignature(signature: Uint8Array, key: ArkgSigningKey, data: Uint8Array) {
	const candidates: Uint8Array[] = [];
	try {
		candidates.push(p256.Signature.fromBytes(signature, 'der').toBytes('compact'));
	} catch {
		/* Some preview clients return the COSE/P1363 form directly. */
	}
	if (signature.length === 64) candidates.push(signature);
	const publicKey = await crypto.subtle.importKey('jwk', key.publicKey, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
		'verify',
	]);
	for (const compact of candidates) {
		if (
			await crypto.subtle.verify(
				{ name: 'ECDSA', hash: 'SHA-256' },
				publicKey,
				Uint8Array.from(compact),
				Uint8Array.from(data),
			)
		)
			return compact;
	}
	throw new Error('Hardware signature does not match the holder key and signing input');
}

export function createPreviewSignClient(post: Post): PreviewSignClient {
	return {
		async sign(seed, key, data) {
			requireEnabled();
			const { data: begin } = await post('/user/session/preview-sign/sign-begin', { seedId: seed.id });
			const { assertion } = await requestPreviewSignature(seed, key, data, begin.challenge);
			// Only use extension bytes covered by the server-verified assertion.
			const { data: verified } = await post('/user/session/preview-sign/sign-finish', {
				challengeId: begin.challengeId,
				seedId: seed.id,
				credential: serializeWebauthnCredential(assertion),
			});
			return verifyHardwareSignature(fromBase64Url(verified.signature), key, data);
		},
	};
}

export function encodeJwtPart(value: object): string {
	return toBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}
