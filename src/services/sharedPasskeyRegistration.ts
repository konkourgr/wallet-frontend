import { PREVIEW_SIGN_ENABLED } from '@/config';
import { AppError } from '@/errors';
import { toBase64Url } from '@/util';
import { addConfigureArkgEvent } from './WalletStateSchema';
import { openPrivateData, updateWalletState, type OpenedContainer } from './keystore';
import { enrollArkgSeed } from './previewSign';

/** Complete signing before exposing the newly initialized/unlocked wallet. */
export async function activateSharedPasskeySigning(
	container: OpenedContainer,
	credentialId: string,
	post: Parameters<typeof enrollArkgSeed>[0],
): Promise<OpenedContainer> {
	if (!PREVIEW_SIGN_ENABLED) return container;
	try {
		const [data, , state] = await openPrivateData(container[1], container[0]);
		const registeredSeed = state.arkgSeeds.find((seed) => seed.credentialId === credentialId);
		if (registeredSeed && state.activeArkgSeedId) return container;
		if (!container[0].prfKeys?.some((key) => toBase64Url(key.credentialId) === credentialId))
			throw new Error('The signing passkey must also unlock this wallet');
		const seed = await enrollArkgSeed(post, credentialId);
		const updated = await addConfigureArkgEvent(data, state.activeArkgSeedId ?? seed.id, seed);
		return (await updateWalletState(container, updated)).newContainer;
	} catch (cause) {
		throw new AppError(
			'hardware_signing_setup_failed',
			`Hardware signing setup failed: ${cause instanceof Error ? cause.message : 'Unknown error'}. Sign in with the same passkey to retry.`,
			{ cause },
		);
	}
}
