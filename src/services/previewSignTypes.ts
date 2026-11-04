import type { JWK } from 'jose';

export const PREVIEW_SIGN_ALGORITHM = -65539;

export type ArkgSeed = {
	attestation?: 'packed' | 'none';
	id: string;
	credentialId: string;
	keyHandle: string;
	publicSeed: string;
	algorithm: typeof PREVIEW_SIGN_ALGORITHM;
	transports?: AuthenticatorTransport[];
};

export type SoftwareSigningKey = {
	type?: 'software'; // Absent in existing wallets.
	kid: string;
	did?: string;
	alg: string;
	publicKey: JWK;
	privateKey: JWK;
};

export type ArkgSigningKey = {
	type: 'arkg';
	kid: string;
	did?: string;
	alg: 'ES256';
	publicKey: JWK;
	seedId: string;
	ticket: string;
	context: string;
};

export type CredentialSigningKey = SoftwareSigningKey | ArkgSigningKey;
