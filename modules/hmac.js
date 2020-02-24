/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Hasher } from "./hasher.js"
import { Utf8 } from "./enc-utf8.js"

/**
 * HMAC algorithm.
 */
export class HMAC {
	/**
	 * @param {Hasher} hasher The hash algorithm to use.
	 * @param {WordArray|string} key The secret key.
	 *
	 * @example
	 *
	 *     let hmacHasher = new HMAC(new SHA256(), key);
	 */
	constructor(hasher, key) {
		// Init hasher
		this._hasher = hasher;

		// Convert string to WordArray, else assume WordArray already
		if (typeof key == 'string') {
			key = Utf8.parse(key);
		}

		// Shortcuts
		let hasherBlockSize = hasher.blockSize;
		let hasherBlockSizeBytes = hasherBlockSize * 4;

		// Allow arbitrary length keys
		if (key.sigBytes > hasherBlockSizeBytes) {
			key = hasher.finalize(key);
		}

		// Clamp excess bits
		key.clamp();

		// Clone key for inner and outer pads
		let oKey = this._oKey = /** @type {WordArray} */ ( platform.clone(key) );
		let iKey = this._iKey = /** @type {WordArray} */ ( platform.clone(key) );

		// Shortcuts
		let oKeyWords = oKey.words;
		let iKeyWords = iKey.words;

		// XOR keys with pad constants
		for (let i = 0; i < hasherBlockSize; i++) {
			oKeyWords[i] ^= 0x5c5c5c5c;
			iKeyWords[i] ^= 0x36363636;
		}
		oKey.sigBytes = iKey.sigBytes = hasherBlockSizeBytes;

		// Set initial values
		this.reset();
	}

	/**
	 * Resets this HMAC to its initial state.
	 *
	 * @example
	 *
	 *     hmacHasher.reset();
	 */
	reset() {
		// Shortcut
		let hasher = this._hasher;

		// Reset
		hasher.reset();
		hasher.update(this._iKey);
	}

	/**
	 * Updates this HMAC with a message.
	 *
	 * @param {WordArray|string} messageUpdate The message to append.
	 *
	 * @return {HMAC} This HMAC instance.
	 *
	 * @example
	 *
	 *     hmacHasher.update('message');
	 *     hmacHasher.update(wordArray);
	 */
	update(messageUpdate) {
		this._hasher.update(messageUpdate);

		// Chainable
		return this;
	}

	/**
	 * Finalizes the HMAC computation.
	 * Note that the finalize operation is effectively a destructive, read-once operation.
	 *
	 * @param {(WordArray|string)=} messageUpdate (Optional) A final message update.
	 *
	 * @return {WordArray} The HMAC.
	 *
	 * @example
	 *
	 *     let hmac = hmacHasher.finalize();
	 *     let hmac = hmacHasher.finalize('message');
	 *     let hmac = hmacHasher.finalize(wordArray);
	 */
	finalize(messageUpdate) {
		// Shortcut
		let hasher = this._hasher;

		// Compute HMAC
		let innerHash = hasher.finalize(messageUpdate);
		hasher.reset();
		let oKey = /** @type {WordArray} */ ( platform.clone(this._oKey) );
		let hmac = hasher.finalize(oKey.concat(innerHash));

		return hmac;
	}
}
