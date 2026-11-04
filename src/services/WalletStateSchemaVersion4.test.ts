import { describe, expect, it } from 'vitest';
import {
	addConfigureArkgEvent,
	addNewKeypairEvent,
	CurrentSchema,
	foldOldEventsIntoBaseState,
	foldState,
	mergeEventHistories,
	SchemaV3,
} from './WalletStateSchema';
import type { ArkgSeed, ArkgSigningKey } from './previewSignTypes';

const seed: ArkgSeed = {
	id: 'seed-a',
	credentialId: 'Y3JlZA',
	keyHandle: 'aGFuZGxl',
	publicSeed: 'c2VlZA',
	algorithm: -65539,
};
const key: ArkgSigningKey = {
	type: 'arkg',
	kid: 'holder',
	alg: 'ES256',
	publicKey: { kty: 'EC', crv: 'P-256' },
	seedId: seed.id,
	ticket: 'dGlja2V0',
	context: 'Y3R4',
};

describe('wallet signing metadata schema', () => {
	it('migrates v3 wallets without rewriting existing software keys', () => {
		const legacy = SchemaV3.WalletStateOperations.initialWalletStateContainer();
		const software = { kid: 'legacy', alg: 'ES256', publicKey: {}, privateKey: { d: 'private' } };
		legacy.S = { ...legacy.S, keypairs: [{ kid: software.kid, keypair: software }] } as SchemaV3.WalletState;
		const migrated = foldState(legacy);
		expect(migrated.keypairs[0].keypair).toEqual(software);
		expect(migrated.arkgSeeds).toEqual([]);
		expect(migrated.activeArkgSeedId).toBeNull();
		expect(legacy.S.schemaVersion).toBe(3);
	});

	it('preserves seeds and private-key-free ARKG records when folding history', async () => {
		let container = CurrentSchema.WalletStateOperations.initialWalletStateContainer();
		container = await addConfigureArkgEvent(container, seed.id, seed);
		container = await addNewKeypairEvent(container, key.kid, key);
		container = await addConfigureArkgEvent(container, null);
		const expected = foldState(container);
		const folded = await foldOldEventsIntoBaseState(container, -1);
		expect(folded.events).toEqual([]);
		expect(foldState(folded)).toEqual(expected);
		expect(expected.arkgSeeds).toEqual([seed]);
		expect(expected.activeArkgSeedId).toBeNull();
		expect(expected.keypairs[0].keypair).not.toHaveProperty('privateKey');
	});

	it('retains seeds and holder keys from divergent histories, including enrollment after issuance', async () => {
		const base = CurrentSchema.WalletStateOperations.initialWalletStateContainer();
		const a = await addNewKeypairEvent(await addConfigureArkgEvent(base, seed.id, seed), key.kid, key);
		const other = { ...seed, id: 'seed-b' };
		const b = await addConfigureArkgEvent(base, other.id, other);
		for (const [left, right] of [
			[a, b],
			[b, a],
		]) {
			const merged = (await mergeEventHistories(left, right)) as CurrentSchema.WalletStateContainer;
			expect(
				foldState(merged)
					.arkgSeeds.map((s) => s.id)
					.sort(),
			).toEqual(['seed-a', 'seed-b']);
			expect(foldState(merged).keypairs[0].keypair).toEqual(key);
			await CurrentSchema.WalletStateOperations.validateEventHistoryContinuity(merged);
		}
	});

	it('rejects selection of an unknown seed', async () => {
		await expect(
			addConfigureArkgEvent(CurrentSchema.WalletStateOperations.initialWalletStateContainer(), 'missing'),
		).rejects.toThrow('seed not found');
	});
});
