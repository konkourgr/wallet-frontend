import { useTranslation } from 'react-i18next';
import { useSessionContext } from '@/context/SessionContext';
import type { WebauthnCredential } from '@/api/types';
import { toBase64Url } from '@/util';

export default function HardwareSigning({ credentials }: { credentials: WebauthnCredential[] }) {
	const { keystore } = useSessionContext();
	const { t } = useTranslation();
	const state = keystore.getCalculatedWalletState();
	const active = state?.arkgSeeds.find((seed) => seed.id === state.activeArkgSeedId);
	const passkey = credentials.find((credential) => toBase64Url(credential.credentialId) === active?.credentialId);
	return (
		<div className="flex flex-col gap-3">
			<p className="text-sm">
				{t('hardwareSigning.automatic', {
					defaultValue:
						'Hardware signing is configured automatically when you register a compatible passkey. The same passkey unlocks the wallet and signs with ARKG.',
				})}
			</p>
			<p role="status" className="text-sm">
				{active && passkey
					? t('hardwareSigning.active', {
							defaultValue: 'Hardware signing active: {{name}}',
							name: passkey.name || 'Security key',
						})
					: t('hardwareSigning.incomplete', {
							defaultValue:
								'Hardware signing setup is incomplete. Sign in again with the compatible passkey to retry setup, or add a new compatible passkey if yours was registered without previewSign.',
						})}
			</p>
			<p className="text-sm">
				{t('hardwareSigning.recovery', {
					defaultValue:
						'Keep the original signing key: restoring your wallet backup does not restore its hardware signing capability. Removing a shared passkey also removes its signing access.',
				})}
			</p>
		</div>
	);
}
