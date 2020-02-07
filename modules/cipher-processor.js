/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { BufferedBlockAlgorithm } from "./algo.js"
import { WordArray } from "./wordarray.js"

/**
 * Configuration options.
 *
 * @property {WordArray} iv The IV to use for this operation.
 */
export class ConfigCipher {
	/**
	 * @param {*=} cfg (Optional) The configuration options.
	 */
	constructor(cfg) {
		/** @type {WordArray} */ this.iv;

		let iv = cfg && cfg['iv'] || undefined; if (iv !== undefined && iv instanceof WordArray) this.iv = iv;
	}
}

/**
 * @abstract base cipher template.
 *
 * @property {number} keySize This cipher's key size. Default: 4 (128 bits)
 * @property {number} ivSize This cipher's IV size. Default: 4 (128 bits)
 */
export class CipherProcessor extends BufferedBlockAlgorithm {
	/**
	 * @param {number} xformMode Either the encryption or decryption transormation mode constant.
	 * @param {WordArray} key The key.
	 * @param {*=} cfg (Optional) The configuration options to use for this operation.
	 *
	 * @example
	 *
	 *     let cipher = new AES(ENC_XFORM_MODE, keyWordArray, { iv: ivWordArray });
	 */
	constructor(xformMode, key, cfg) {
		super();

		/** @type {ConfigCipher} */ this.cfg;
		/** @type {number} */ this._xformMode;
		/** @type {WordArray} */ this._key;

		this.init(xformMode, key, cfg);
	}

	/**
	 * Initializes a newly created cipher.
	 *
	 * @param {number} xformMode Either the encryption or decryption transormation mode constant.
	 * @param {WordArray} key The key.
	 * @param {*=} cfg (Optional) The configuration options to use for this operation.
	 */
	init(xformMode, key, cfg) {
		this.updateConfig(cfg);

		// Store transform mode and key
		this._xformMode = xformMode;
		this._key = key;

		// Set initial values
		this.reset();

		return this;
	}

	/**
	 * @param {*=} cfg (Optional) The configuration options to use for this operation.
	 */
	updateConfig(cfg) {
		// Apply config defaults
		this.cfg = new ConfigCipher(cfg);
	}

	/**
	 * Resets this cipher to its initial state.
	 *
	 * @example
	 *
	 *     cipher.reset();
	 */
	reset() {
		// Reset data buffer
		super.reset();

		// Perform concrete-cipher logic
		this._doReset();
	}
	
	/**
	 * @abstract
	 */
	_doReset() {}

	/**
	 * Adds data to be encrypted or decrypted.
	 *
	 * @param {WordArray|string} dataUpdate The data to encrypt or decrypt.
	 *
	 * @return {WordArray} The data after processing.
	 *
	 * @example
	 *
	 *     let encrypted = cipher.process('data');
	 *     let encrypted = cipher.process(wordArray);
	 */
	process(dataUpdate) {
		// Append
		this._append(dataUpdate);

		// Process available blocks
		return this._process();
	}

	/**
	 * Finalizes the encryption or decryption process.
	 * Note that the finalize operation is effectively a destructive, read-once operation.
	 *
	 * @param {WordArray|string} dataUpdate The final data to encrypt or decrypt.
	 *
	 * @return {WordArray} The data after final processing.
	 *
	 * @example
	 *
	 *     let encrypted = cipher.finalize();
	 *     let encrypted = cipher.finalize('data');
	 *     let encrypted = cipher.finalize(wordArray);
	 */
	finalize(dataUpdate) {
		// Final data update
		if (dataUpdate) {
			this._append(dataUpdate);
		}

		// Perform concrete-cipher logic
		let finalProcessedData = this._doFinalize();

		return finalProcessedData;
	}

	/**
	 * @abstract
	 * @returns {WordArray}
	 */
	_doFinalize() {}

	/**
	 * @abstract
	 * @param {Array<number>} M 
	 * @param {number} offset 
	 */
	encryptBlock(M, offset) {}

	/**
	 * @abstract
	 * @param {Array<number>} M 
	 * @param {number} offset 
	 */
	decryptBlock(M, offset) {}
}
