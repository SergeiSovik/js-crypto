/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Hasher } from "./hasher.js"
import { HasherMD5 } from "./md5.js"

/**
 * Configuration options.
 *
 * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
 * @property {Hasher} hasher The hash algorithm to use. Default: MD5
 * @property {number} iterations The number of iterations to perform. Default: 1
 */
class ConfigEvpKDF {
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
			this.hasher = new HasherMD5();
		}
	}
}

/**
 * This key derivation function is meant to conform with EVP_BytesToKey.
 * www.openssl.org/docs/crypto/EVP_BytesToKey.html
 */
export class ClassEvpKDF {
	/**
	 * @param {*=} cfg 
	 */
	constructor(cfg) {
		/** @type {ConfigEvpKDF} */ this.cfg;

		this.init(cfg);
	}

	/**
	 * Initializes a newly created key derivation function.
	 *
	 * @param {*=} cfg (Optional) The configuration options to use for the derivation.
	 *
	 * @example
	 *
	 *     let kdf = new EvpKDF();
	 *     let kdf = new EvpKDF({ 'keySize': 8 });
	 *     let kdf = new EvpKDF({ 'keySize': 8, 'iterations': 1000 });
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
		this.cfg = new ConfigEvpKDF(cfg);
	}

	/**
	 * Derives a key from a password.
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

		// Init hasher
		let hasher = cfg.hasher;

		// Initial values
		let derivedKey = new WordArray();

		// Shortcuts
		let derivedKeyWords = derivedKey.words;
		let keySize = cfg.keySize;
		let iterations = cfg.iterations;

		// Generate key
		/** @type {WordArray} */ let block;
		while (derivedKeyWords.length < keySize) {
			if (block) {
				hasher.update(block);
			}
			block = hasher.update(password).finalize(salt);
			hasher.reset();

			// Iterations
			for (let i = 1; i < iterations; i++) {
				block = hasher.finalize(block);
				hasher.reset();
			}

			derivedKey.concat(block);
		}
		derivedKey.sigBytes = keySize * 4;

		return derivedKey;
	}
}

const _EvpKDF = new ClassEvpKDF();

/**
 * Derives a key from a password.
 *
 * @param {WordArray|string} password The password.
 * @param {WordArray|string} salt A salt.
 * @param {*=} cfg (Optional) The configuration options to use for this computation.
 *
 * @return {WordArray} The derived key.
 *
 * @example
 *
 *     let key = EvpKDF(password, salt);
 *     let key = EvpKDF(password, salt, { keySize: 8 });
 *     let key = EvpKDF(password, salt, { keySize: 8, iterations: 1000 });
 */
export function EvpKDF(password, salt, cfg) {
	return _EvpKDF.init(cfg).compute(password, salt);
}
