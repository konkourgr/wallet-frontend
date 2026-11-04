import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import axios from 'axios';
import { useApi } from './index';
import type { LocalStorageKeystore } from '@/services/LocalStorageKeystore';
import type { OpenedContainer } from '@/services/keystore';
import { activateSharedPasskeySigning } from '@/services/sharedPasskeyRegistration';
import { AppError } from '@/errors';

vi.mock('axios', () => ({ default: { post: vi.fn(), get: vi.fn(), isAxiosError: () => false } }));
vi.mock('react-router-dom', () => ({ useNavigate: () => vi.fn() }));
vi.mock('@/config', () => ({ BACKEND_URL: 'http://wallet.test', PREVIEW_SIGN_ENABLED: true }));
vi.mock('@/indexedDB', () => ({
	addItem: vi.fn(async () => undefined),
	getItem: vi.fn(async () => null),
	EXCLUDED_INDEXEDDB_PATHS: new Set(),
}));
vi.mock('@/services/sharedPasskeyRegistration', () => ({ activateSharedPasskeySigning: vi.fn() }));
vi.mock('@/services/previewSign', () => ({
	combinedRegistrationExtensions: (value: object) => value,
	getSigningAttestation: () => new Uint8Array([42]),
}));
vi.mock('@/services/keystore', () => ({
	serializePrivateData: (data: { jwe: string }) => new TextEncoder().encode(data.jwe),
	parsePrivateData: async () => original[0],
}));

const original = [{ jwe: 'initial' }, {}] as OpenedContainer;
const configured = [{ jwe: 'with-arkg' }, {}] as OpenedContainer;
const credential = {
	id: 'shared-passkey',
	rawId: new Uint8Array([1]),
	type: 'public-key',
	response: { getTransports: () => ['usb'] },
	getClientExtensionResults: () => ({}),
} as unknown as PublicKeyCredential;

beforeEach(() => {
	window.localStorage.clear();
	window.sessionStorage.clear();
	vi.stubGlobal('navigator', {
		credentials: {
			create: vi.fn(async () => credential),
			get: vi.fn(async () => ({ ...credential, response: { userHandle: new TextEncoder().encode('new-user') } })),
		},
	});
	vi.mocked(axios.get).mockResolvedValue({ data: {}, headers: {} });
	vi.mocked(axios.post).mockImplementation(async (url) => {
		if (String(url).endsWith('register-webauthn-begin'))
			return {
				data: {
					challengeId: 'create',
					createOptions: {
						publicKey: { user: { id: new Uint8Array([1]) }, authenticatorSelection: {} },
					},
				},
				headers: {},
			};
		if (String(url).endsWith('register-webauthn-finish'))
			return { data: { uuid: 'new-user', appToken: 'new-token' }, headers: { 'x-private-data-etag': 'initial-etag' } };
		if (String(url).endsWith('login-webauthn-begin'))
			return { data: { challengeId: 'login', getOptions: { publicKey: {} } }, headers: {} };
		if (String(url).endsWith('login-webauthn-finish'))
			return {
				data: { uuid: 'new-user', appToken: 'new-token', privateData: new Uint8Array([1]) },
				headers: { 'x-private-data-etag': 'initial-etag' },
			};
		if (String(url).endsWith('/private-data'))
			return { status: 204, data: '', headers: { 'x-private-data-etag': 'arkg-etag' } };
		return { data: {}, headers: {} };
	});
	vi.mocked(activateSharedPasskeySigning).mockImplementation(async (_container, _credentialId, post) => {
		await post('/user/session/preview-sign/register-begin', { credentialId: credential.id });
		await post('/user/session/preview-sign/register-complete', { credential });
		return configured;
	});
});

afterEach(() => {
	cleanup();
	vi.clearAllMocks();
	vi.unstubAllGlobals();
});

function newKeystore() {
	return {
		initPrf: vi.fn(async (_credential, _salt, _prompt, _user, prepare) => {
			const result = await prepare(original);
			return result[0];
		}),
	} as unknown as LocalStorageKeystore;
}

describe('automatic signing during wallet signup', () => {
	it('verifies and uploads ARKG state using the new token before publishing the session', async () => {
		const { result } = renderHook(() => useApi());
		const keystore = newKeystore();
		await act(async () => {
			const signup = await result.current.signupWebauthn('Alice', keystore, async () => true, []);
			expect(signup.ok).toBe(true);
		});
		const calls = vi.mocked(axios.post).mock.calls;
		expect(calls.map(([url]) => String(url).replace('http://wallet.test', ''))).toEqual([
			'/user/register-webauthn-begin',
			'/user/register-webauthn-finish',
			'/user/session/preview-sign/register-begin',
			'/user/session/preview-sign/register-complete',
			'/user/session/private-data',
		]);
		for (const [, , options] of calls.slice(2)) expect(options?.headers?.Authorization).toBe('Bearer new-token');
		expect(calls[4][1]).toEqual(new TextEncoder().encode('with-arkg'));
		expect(calls[4][2]?.headers?.['X-Private-Data-If-Match']).toBe('initial-etag');
		expect(window.localStorage.getItem('privateDataEtag')).toBe('"arkg-etag"');
		expect(result.current.isLoggedIn()).toBe(true);
	});

	it('does not publish a logged-in session or upload software state when signing setup fails', async () => {
		vi.mocked(activateSharedPasskeySigning).mockRejectedValue(
			new AppError('hardware_signing_setup_failed', 'Backend signing is disabled'),
		);
		const { result } = renderHook(() => useApi());
		await act(async () => {
			const signup = await result.current.signupWebauthn('Alice', newKeystore(), async () => true, []);
			expect(signup.err).toBe(true);
			expect(signup.val).toEqual({ errorId: 'hardwareSigningSetupFailed', message: 'Backend signing is disabled' });
		});
		expect(result.current.isLoggedIn()).toBe(false);
		expect(window.sessionStorage.getItem('appToken')).toBeNull();
		expect(vi.mocked(axios.post).mock.calls).toHaveLength(2);
	});
});

describe('automatic recovery on login', () => {
	it('retries setup with the same credential and login token before completing login', async () => {
		const { result } = renderHook(() => useApi());
		const keystore = {
			unlockPrf: vi.fn(async (_data, _credential, _prompt, _user, prepare) => {
				const configured = await prepare(original);
				return [configured[0], async () => {}];
			}),
		} as unknown as LocalStorageKeystore;
		await act(async () => {
			expect((await result.current.loginWebauthn(keystore, async () => true, [], undefined)).ok).toBe(true);
		});
		const calls = vi.mocked(axios.post).mock.calls;
		expect(calls.map(([url]) => String(url).replace('http://wallet.test', ''))).toEqual([
			'/user/login-webauthn-begin',
			'/user/login-webauthn-finish',
			'/user/session/preview-sign/register-begin',
			'/user/session/preview-sign/register-complete',
			'/user/session/private-data',
		]);
		expect(vi.mocked(activateSharedPasskeySigning).mock.calls[0][1]).toBe(credential.id);
		for (const [, , options] of calls.slice(2)) expect(options?.headers?.Authorization).toBe('Bearer new-token');
		expect(result.current.isLoggedIn()).toBe(true);
	});
});
