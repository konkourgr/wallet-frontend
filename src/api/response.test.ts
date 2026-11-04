import { describe, expect, it } from 'vitest';
import axios, { AxiosError } from 'axios';
import { transformResponse } from './response';

describe('backend response parsing', () => {
	it('decodes JSON and tagged binary responses', () => {
		expect(transformResponse('{"seed":{"$b64u":"AQID"}}')).toEqual({ seed: new Uint8Array([1, 2, 3]) });
	});
	it.each(['Not Found', '<html>Bad Gateway</html>', 'Unauthorized', ''])(
		'preserves non-JSON errors: %s',
		async (data) => {
			const client = axios.create({
				transformResponse,
				adapter: async (config) => {
					const response = { config, status: 404, statusText: 'Not Found', headers: {}, data };
					throw new AxiosError('Request failed with status code 404', 'ERR_BAD_REQUEST', config, undefined, response);
				},
			});
			await expect(client.post('/preview-sign/register-begin')).rejects.toMatchObject({
				response: { status: 404, data },
			});
		},
	);
});
