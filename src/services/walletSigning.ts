import type { JWK } from 'jose';
import { toBase64Url } from '@/util';
import type { ArkgSeed, CredentialSigningKey } from './previewSignTypes';
import { encodeJwtPart, type PreviewSignClient } from './previewSign';

export async function signWithWalletKey(
	key: CredentialSigningKey,
	seeds: ArkgSeed[],
	data: Uint8Array,
	hardware?: PreviewSignClient,
): Promise<Uint8Array> {
	if (key.type === 'arkg') {
		const seed = seeds.find((candidate) => candidate.id === key.seedId);
		if (!seed) throw new Error('ARKG seed not found; this credential requires its original signing key');
		if (!hardware) throw new Error('Hardware signing is unavailable in this session');
		return hardware.sign(seed, key, data);
	}
	if (key.alg !== 'ES256') throw new Error('Unsupported wallet signing algorithm');
	const privateKey = await crypto.subtle.importKey(
		'jwk',
		key.privateKey,
		{ name: 'ECDSA', namedCurve: 'P-256' },
		false,
		['sign'],
	);
	return new Uint8Array(
		await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, Uint8Array.from(data)),
	);
}

export async function signWalletJwt(
	payload: object,
	header: { alg: string; typ: string; jwk?: JWK },
	key: CredentialSigningKey,
	seeds: ArkgSeed[],
	hardware?: PreviewSignClient,
): Promise<string> {
	const input = `${encodeJwtPart(header)}.${encodeJwtPart({ ...payload, iat: Math.floor(Date.now() / 1000) })}`;
	const signature = await signWithWalletKey(key, seeds, new TextEncoder().encode(input), hardware);
	return `${input}.${toBase64Url(signature)}`;
}
