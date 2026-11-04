import * as SchemaV3 from './WalletStateSchemaVersion3';
import type * as SchemaV2 from './WalletStateSchemaVersion2';
import type * as Common from './WalletStateSchemaCommon';
import type { ArkgSeed, CredentialSigningKey } from './previewSignTypes';

export * from './WalletStateSchemaVersion3';
export const SCHEMA_VERSION = 4;
export type CredentialKeyPair = CredentialSigningKey;
export type WalletState = Omit<SchemaV3.WalletState, 'keypairs'> & {
	keypairs: { kid: string; keypair: CredentialSigningKey }[];
	arkgSeeds: ArkgSeed[];
	activeArkgSeedId: string | null;
};
export type WalletSessionEventConfigureArkg = Common.WalletSessionEvent & {
	type: 'configure_arkg';
	seed?: ArkgSeed;
	activeSeedId: string | null;
};
export type WalletSessionEvent =
	| Exclude<SchemaV3.WalletSessionEvent, SchemaV3.WalletSessionEventNewKeypair>
	| (Common.WalletSessionEvent & { type: 'new_keypair'; kid: string; keypair: CredentialSigningKey })
	| WalletSessionEventConfigureArkg;
export type WalletStateContainer = {
	S: SchemaV3.WalletStateV3OrEarlier | WalletState;
	events: WalletSessionEvent[];
	lastEventHash: string;
};
export type WalletStateKeypair = WalletState['keypairs'][number];

function migrateState(state: WalletStateContainer['S']): WalletState {
	if (state.schemaVersion > SCHEMA_VERSION) throw new Error('Unsupported future wallet schema');
	if (state.schemaVersion === SCHEMA_VERSION) return state as WalletState;
	return {
		...SchemaV3.WalletStateOperations.migrateState(state as SchemaV3.WalletStateV3OrEarlier),
		schemaVersion: SCHEMA_VERSION,
		arkgSeeds: [],
		activeArkgSeedId: null,
	};
}

function walletStateReducer(state: WalletStateContainer['S'], event: WalletSessionEvent): WalletStateContainer['S'] {
	if (event.type === 'configure_arkg') {
		const current = migrateState(state);
		const seeds =
			event.seed && !current.arkgSeeds.some((seed) => seed.id === event.seed?.id)
				? [...current.arkgSeeds, event.seed]
				: current.arkgSeeds;
		if (event.activeSeedId && !seeds.some((seed) => seed.id === event.activeSeedId)) {
			throw new Error('ARKG signing seed not found');
		}
		return { ...current, arkgSeeds: seeds, activeArkgSeedId: event.activeSeedId };
	}
	if (event.schemaVersion < SCHEMA_VERSION && state.schemaVersion < SCHEMA_VERSION) {
		return SchemaV3.WalletStateOperations.walletStateReducer(
			state as SchemaV3.WalletStateV3OrEarlier,
			event as SchemaV3.WalletSessionEvent,
		);
	}
	const current = migrateState(state);
	if (event.type === 'new_keypair') {
		if ('wrappedPrivateKey' in event.keypair) throw new Error('Legacy signing key must be migrated before use');
		return {
			...current,
			keypairs: [
				...current.keypairs.filter((key) => key.kid !== event.kid),
				{ kid: event.kid, keypair: event.keypair },
			],
		};
	}
	// Existing reducers don't inspect private-key fields. Keep the v3 reducer
	// and event hash format intact for all the pre-existing event types.
	const reduced = SchemaV3.WalletStateOperations.walletStateReducer(
		{ ...current, schemaVersion: 3 } as SchemaV3.WalletState,
		{ ...event, schemaVersion: 3 } as SchemaV3.WalletSessionEvent,
	);
	return {
		...reduced,
		schemaVersion: SCHEMA_VERSION,
		arkgSeeds: current.arkgSeeds,
		activeArkgSeedId: current.activeArkgSeedId,
	} as WalletState;
}

const v4ops = SchemaV3.createOperations(SCHEMA_VERSION, SchemaV3.mergeStrategies);

export const WalletStateOperations = {
	...v4ops,
	migrateState,
	walletStateReducer,
	initialWalletStateContainer(): WalletStateContainer {
		const container = SchemaV3.WalletStateOperations.initialWalletStateContainer();
		return { ...container, S: migrateState(container.S) };
	},
	async mergeDivergentHistoriesWithStrategies(
		earlier: Common.WalletSessionEvent[],
		a: WalletSessionEvent[],
		b: WalletSessionEvent[],
		parentHash: string,
	): Promise<Common.WalletSessionEvent[]> {
		const legacy = (events: Common.WalletSessionEvent[]) =>
			events.filter((event) => event.type !== 'configure_arkg') as SchemaV2.WalletSessionEvent[];
		const merged = await v4ops.mergeDivergentHistoriesWithStrategies(legacy(earlier), legacy(a), legacy(b), parentHash);
		const seen = new Set(earlier.map((event) => event.eventId));
		const configuration = [...a, ...b].filter((event) => {
			if (event.type !== 'configure_arkg' || seen.has(event.eventId)) return false;
			seen.add(event.eventId);
			return true;
		});
		if (configuration.length === 0) return merged;
		const order = new Map([...a, ...b].map((event, index) => [event.eventId, index]));
		return v4ops.rebuildEventHistory(
			[...merged, ...configuration].sort(
				(x, y) => x.timestampSeconds - y.timestampSeconds || order.get(x.eventId)! - order.get(y.eventId)!,
			),
			parentHash,
		);
	},
};
