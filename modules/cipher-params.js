/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Cipher } from "./cipher-core.js"
import { Mode } from "./mode.js"
import { Padding } from "./padding.js"
import { Formatter } from "./format.js"

/**
 * A collection of cipher parameters.
 *
 * @property {WordArray} ciphertext The raw ciphertext.
 * @property {WordArray} key The key to this ciphertext.
 * @property {WordArray} iv The IV used in the ciphering operation.
 * @property {WordArray} salt The salt used with a key derivation function.
 * @property {Cipher} algorithm The cipher algorithm.
 * @property {Mode} mode The block mode used in the ciphering operation.
 * @property {Padding} padding The padding scheme used in the ciphering operation.
 * @property {number} blockSize The block size of the cipher.
 * @property {Formatter} formatter The default formatting strategy to convert this cipher params object to a string.
 */
export class CipherParams {
	/**
	 * @param {*=} cfg An object with any of the possible cipher parameters.
	 *
	 * @example
	 *
	 *     let cipherParams = new CipherParams({
	 *         'ciphertext': ciphertextWordArray,
	 *         'key': keyWordArray,
	 *         'iv': ivWordArray,
	 *         'salt': saltWordArray,
	 *         'algorithm': CryptoJS.AES,
	 *         'mode': CryptoJS.CBC,
	 *         'padding': CryptoJS.PKCS7,
	 *         'blockSize': 4,
	 *         'formatter': CryptoJS.OpenSSL
	 *     });
	 */
	constructor(cfg) {
		/** @type {WordArray} */ this.ciphertext;
		/** @type {WordArray} */ this.key;
		/** @type {WordArray} */ this.iv;
		/** @type {WordArray} */ this.salt;
		/** @type {Cipher} */ this.algorithm;
		/** @type {Mode} */ this.mode;
		/** @type {Padding} */ this.padding;
		/** @type {number} */ this.blockSize;
		/** @type {Formatter} */ this.formatter;

		let ciphertext = cfg && cfg['ciphertext'] || undefined; if (ciphertext !== undefined && ciphertext instanceof WordArray) this.ciphertext = ciphertext;
		let key = cfg && cfg['key'] || undefined; if (key !== undefined && key instanceof WordArray) this.key = key;
		let iv = cfg && cfg['iv'] || undefined; if (iv !== undefined && iv instanceof WordArray) this.iv = iv;
		let salt = cfg && cfg['salt'] || undefined; if (salt !== undefined && salt instanceof WordArray) this.salt = salt;
		let algorithm = cfg && cfg['algorithm'] || undefined; if (algorithm !== undefined && algorithm instanceof Cipher) this.algorithm = algorithm;
		let mode = cfg && cfg['mode'] || undefined; if (mode !== undefined && mode instanceof Mode) this.mode = mode;
		let padding = cfg && cfg['padding'] || undefined; if (padding !== undefined && padding instanceof Padding) this.padding = padding;
		let blockSize = cfg && cfg['blockSize'] || undefined; if (blockSize !== undefined && typeof blockSize === 'number') this.blockSize = blockSize;
		let formatter = cfg && cfg['formatter'] || undefined; if (formatter !== undefined && formatter instanceof Formatter) this.formatter = formatter;
	}

	/**
	 * @param {CipherParams} cfg 
	 */
	mixIn(cfg) {
		if (cfg.ciphertext !== undefined) this.ciphertext = cfg.ciphertext;
		if (cfg.key !== undefined) this.key = cfg.key;
		if (cfg.iv !== undefined) this.iv = cfg.iv;
		if (cfg.salt !== undefined) this.salt = cfg.salt;
		if (cfg.algorithm !== undefined) this.algorithm = cfg.algorithm;
		if (cfg.mode !== undefined) this.mode = cfg.mode;
		if (cfg.padding !== undefined) this.padding = cfg.padding;
		if (cfg.blockSize !== undefined) this.blockSize = cfg.blockSize;
		if (cfg.formatter !== undefined) this.formatter = cfg.formatter;
	}

	/**
	 * Converts this cipher params object to a string.
	 *
	 * @param {Formatter=} formatter (Optional) The formatting strategy to use.
	 *
	 * @return {string} The stringified cipher params.
	 *
	 * @throws Error If neither the formatter nor the default formatter is set.
	 *
	 * @example
	 *
	 *     let string = cipherParams + '';
	 *     let string = cipherParams.toString();
	 *     let string = cipherParams.toString(CryptoJS.format.OpenSSL);
	 */
	toString(formatter) {
		return (formatter || this.formatter).stringify(this);
	}
}
