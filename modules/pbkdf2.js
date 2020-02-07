/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Hasher } from "./hasher.js"
import { HasherSHA1 } from "./sha1.js"
import { HMAC } from "./hmac.js"

/**
 * Configuration options.
 *
 * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
 * @property {Hasher} hasher The hasher to use. Default: SHA1
 * @property {number} iterations The number of iterations to perform. Default: 1
 */
class ConfigPBKDF2 {
	/**
	 * @param {*=} cfg (Optional) The configuration options to use for the derivation.
	 */
	constructor(cfg) {
		/** @type {number} */ this.keySize = 128/32;
		/** @type {Hasher} */ this.hasher;
		/** @type {number} */ this.iterations = 1;

		let keySize = cfg && cfg['keySize'] || undefined; if (keySize !== undefined && typeof keySize === 'number') this.keySize = keySize;
		let hasher = cfg && cfg['hasher'] || undefined; if (hasher !== undefined && hasher instanceof Hasher) this.hasher = hasher;
		let iterations = cfg && cfg['iterations'] || undefined; if (iterations !== undefined && typeof iterations === 'number') this.iterations = iterations;

		if (this.hasher === undefined) {
			this.hasher = new HasherSHA1();
		}
	}
}

/**
 * Password-Based Key Derivation Function 2 algorithm.
 */
export class ClassPBKDF2 {
	/**
	 * @param {*=} cfg 
	 */
	constructor(cfg) {
		/** @type {ConfigPBKDF2} */ this.cfg;

		this.init(cfg);
	}

	/**
	 * Initializes a newly created key derivation function.
	 *
	 * @param {*=} cfg (Optional) The configuration options to use for the derivation.
	 *
	 * @example
	 *
	 *     let kdf = new PBKDF2();
	 *     let kdf = new PBKDF2({ 'keySize': 8 });
	 *     let kdf = new PBKDF2({ 'keySize': 8, 'iterations': 1000 });
	 */
	init(cfg) {
		this.updateConfig(cfg);

		return this;
	}

	/**
	 * @param {*=} cfg (Optional) The configuration options to use for this operation.
	 */
	updateConfig(cfg) {
		// Apply config defaults
		this.cfg = new ConfigPBKDF2(cfg);
	}

	/**
	 * Computes the Password-Based Key Derivation Function 2.
	 *
	 * @param {WordArray|string} password The password.
	 * @param {WordArray|string} salt A salt.
	 *
	 * @return {WordArray} The derived key.
	 *
	 * @example
	 *
	 *     let key = kdf.compute(password, salt);
	 */
	compute(password, salt) {
		// Shortcut
		let cfg = this.cfg;

		// Init HMAC
		let hmac = new HMAC(cfg.hasher, password);

		// Initial values
		let derivedKey = new WordArray();
		let blockIndex = new WordArray([0x00000001]);

		// Shortcuts
		let derivedKeyWords = derivedKey.words;
		let blockIndexWords = blockIndex.words;
		let keySize = cfg.keySize;
		let iterations = cfg.iterations;

		// Generate key
		while (derivedKeyWords.length < keySize) {
			let block = hmac.update(salt).finalize(blockIndex);
			hmac.reset();

			// Shortcuts
			let blockWords = block.words;
			let blockWordsLength = blockWords.length;

			// Iterations
			let intermediate = block;
			for (let i = 1; i < iterations; i++) {
				intermediate = hmac.finalize(intermediate);
				hmac.reset();

				// Shortcut
				let intermediateWords = intermediate.words;

				// XOR intermediate with block
				for (let j = 0; j < blockWordsLength; j++) {
					blockWords[j] ^= intermediateWords[j];
				}
			}

			derivedKey.concat(block);
			blockIndexWords[0]++;
		}
		derivedKey.sigBytes = keySize * 4;

		return derivedKey;
	}
}

const _PBKDF2 = new ClassPBKDF2();

/**
 * Computes the Password-Based Key Derivation Function 2.
 *
 * @param {WordArray|string} password The password.
 * @param {WordArray|string} salt A salt.
 * @param {*=} cfg (Optional) The configuration options to use for this computation.
 *
 * @return {WordArray} The derived key.
 *
 * @static
 *
 * @example
 *
 *     let key = PBKDF2(password, salt);
 *     let key = PBKDF2(password, salt, { keySize: 8 });
 *     let key = PBKDF2(password, salt, { keySize: 8, iterations: 1000 });
 */
export function PBKDF2(password, salt, cfg) {
	return _PBKDF2.init(cfg).compute(password, salt);
}
