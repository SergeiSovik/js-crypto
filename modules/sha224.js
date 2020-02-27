/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { HasherSHA256 } from "./sha256.js"
import { HMAC } from "./hmac.js"

/**
 * SHA-224 hash algorithm.
 */
export class HasherSHA224 extends HasherSHA256 {
	_doReset() {
		this._hash = new WordArray([
			0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
			0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
		]);
	}

	_doFinalize() {
		let hash = super._doFinalize();

		hash.sigBytes -= 4;

		return hash;
	}
}

const _SHA224 = new HasherSHA224();

/**
 * Shortcut function to the hasher's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 *
 * @return {WordArray} The hash.
 *
 * @example
 *
 *     let hash = SHA224('message');
 *     let hash = SHA224(wordArray);
 */
export function SHA224(message) {
	return _SHA224.init().finalize(message);
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
 *     let hmac = HmacSHA224(message, key);
 */
export function HmacSHA224(message, key) {
	return new HMAC(_SHA224, key).finalize(message);
}
