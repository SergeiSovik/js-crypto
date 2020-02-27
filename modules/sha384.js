/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { HasherSHA512 } from "./sha512.js"
import { HMAC } from "./hmac.js"

/**
 * SHA-384 hash algorithm.
 */
export class HasherSHA384 extends HasherSHA512 {
	_doReset() {
		this._hash = new WordArray([
			0xcbbb9d5d, 0xc1059ed8, 0x629a292a, 0x367cd507,
			0x9159015a, 0x3070dd17, 0x152fecd8, 0xf70e5939,
			0x67332667, 0xffc00b31, 0x8eb44a87, 0x68581511,
			0xdb0c2e0d, 0x64f98fa7, 0x47b5481d, 0xbefa4fa4
		]);
	}

	/**
	 * @returns {WordArray}
	 */
	_doFinalize() {
		let hash = super._doFinalize();

		hash.sigBytes -= 16;

		return hash;
	}
}

const _SHA384 = new HasherSHA384();

/**
 * Shortcut function to the hasher's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 *
 * @return {WordArray} The hash.
 *
 * @example
 *
 *     let hash = SHA384('message');
 *     let hash = SHA384(wordArray);
 */
export function SHA384(message) {
	return _SHA384.init().finalize(message);
}

/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 * @param {WordArray|string} key The secret key.
 *
 * @return {WordArray} The HMAC.
 *
 * @example
 *
 *     let hmac = HmacSHA384(message, key);
 */
export function HmacSHA384(message, key) {
	return new HMAC(_SHA384, key).finalize(message);
}
