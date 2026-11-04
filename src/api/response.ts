import { jsonParseTaggedBinary } from '@/util';

/** Preserve HTTP errors even when Express or a proxy returns plain text/HTML. */
export function transformResponse(data: unknown): unknown {
	if (typeof data !== 'string' || !data) return data;
	try {
		return jsonParseTaggedBinary(data);
	} catch (error) {
		if (error instanceof SyntaxError) return data;
		throw error;
	}
}
