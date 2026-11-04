import { assert, describe, it } from 'vitest';
import { compareBy, fromBase64Url, jsonParseTaggedBinary, jsonStringifyTaggedBinary, toBase64Url } from './util';

describe('binary views', () => {
	it('encodes only the requested byte range of a pooled buffer', () => {
		const pool = new Uint8Array([99, 1, 2, 3, 99]);
		const view = pool.subarray(1, 4);
		assert.deepEqual(fromBase64Url(toBase64Url(view)), new Uint8Array([1, 2, 3]));
		assert.deepEqual(jsonParseTaggedBinary(jsonStringifyTaggedBinary({ view })).view, new Uint8Array([1, 2, 3]));
		assert.equal(toBase64Url(new DataView(pool.buffer, 1, 3)), toBase64Url(view));
	});
});

describe('compareBy', () => {
	it('sorts by Date objects as expected.', async () => {
		const a = new Date('2025-08-27T00:00:00Z');
		const b = new Date('2025-08-28T00:00:00Z');
		const c = new Date('2025-08-29T00:00:00Z');
		const list = [{ t: c }, { t: a }, { t: b }];
		const comp = compareBy((o: { t: Date }) => o.t);
		assert.deepEqual(
			list.flatMap((a) => list.map((b) => comp(a, b))),
			[0, 1, 1, -1, 0, -1, -1, 1, 0],
		);
		list.sort(comp);
		assert.deepEqual(list, [{ t: a }, { t: b }, { t: c }]);
	});
});
