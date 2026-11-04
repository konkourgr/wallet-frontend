import { describe, expect, it } from 'vitest';
import { Encoder } from 'cbor-x';
import { deriveArkgPublicKey } from './arkg';
import vectors from './arkg.vectors.json';
import { fromBase64Url } from '@/util';

const hex = (value: string) => Uint8Array.from(value.match(/../g)!.map((byte) => parseInt(byte, 16)));
const cose = new Encoder({ useRecords: false, mapsAsObjects: false, tagUint8Array: false, variableMapSize: true });
function cosePoint(point: Uint8Array) {
	return new Map<number, unknown>([
		[1, 2],
		[-1, 1],
		[-2, point.slice(1, 33)],
		[-3, point.slice(33)],
	]);
}
export function vectorSeed(vector = vectors[0]) {
	return cose.encode(
		new Map<number, unknown>([
			[1, -65537],
			[3, -65700],
			[-1, cosePoint(hex(vector.pk_bl))],
			[-2, cosePoint(hex(vector.pk_kem))],
			[-3, -9],
		]),
	);
}

describe('ARKG-P256 public derivation', () => {
	// Published draft-bradleylundberg-cfrg-arkg, July 2026, Appendix A.1.
	// https://yubico.github.io/arkg-rfc/priv-cons-pub-seed-secrecy/draft-bradleylundberg-cfrg-arkg.html
	for (const [index, vector] of vectors.entries()) {
		it(`matches published public key and ticket vector ${index + 1}`, () => {
			const result = deriveArkgPublicKey(vectorSeed(vector), hex(vector.ikm), new TextEncoder().encode(vector.ctx));
			expect(result.ticket).toEqual(hex(vector.kh));
			const rawPublicKey = Uint8Array.from([
				4,
				...fromBase64Url(result.publicKeyJwk.x),
				...fromBase64Url(result.publicKeyJwk.y),
			]);
			expect(rawPublicKey).toEqual(hex(vector.pk_prime));
			expect(result.publicKeyJwk).not.toHaveProperty('d');
		});
	}
	it('rejects unsupported seeds, weak entropy, and overlong contexts', () => {
		expect(() => deriveArkgPublicKey(cose.encode(new Map([[1, 2]])), new Uint8Array(32), new Uint8Array())).toThrow(
			'Unsupported',
		);
		expect(() => deriveArkgPublicKey(vectorSeed(), new Uint8Array(31), new Uint8Array())).toThrow('entropy');
		expect(() => deriveArkgPublicKey(vectorSeed(), new Uint8Array(32), new Uint8Array(65))).toThrow('64');
	});
});
