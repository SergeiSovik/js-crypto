/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { CipherProcessor } from "./cipher-processor.js"

/**
 * @abstract base block cipher mode template.
 */
export class Mode {
	/**
	 * @abstract
	 * Creates this mode for encryption.
	 *
	 * @param {CipherProcessor} cipher A block cipher instance.
	 * @param {Array<number>} iv The IV words.
	 * 
	 * @returns {ModeProcessor}
	 */
	createEncryptor(cipher, iv) {}

	/**
	 * @abstract
	 * Creates this mode for encryption.
	 *
	 * @param {CipherProcessor} cipher A block cipher instance.
	 * @param {Array<number>} iv The IV words.
	 * 
	 * @returns {ModeProcessor}
	 */
	createDecryptor(cipher, iv) {}
}

/**
 * @abstract
 */
export class ModeProcessor {
	/**
	 * @param {CipherProcessor} cipher A block cipher instance.
	 * @param {Array<number>} iv The IV words.
	 *
	 * @example
	 *
	 *     let mode = CryptoJS.CBC.createEncryptor(cipher, iv.words);
	 */
	constructor(cipher, iv) {
		/** @type {CipherProcessor} */ this._cipher;
		/** @type {Array<number> | undefined} */ this._iv;
		/** @type {Array<number>} */ this._prevBlock;

		this.init(cipher, iv);
	}

	/**
	 * Initializes a newly created mode.
	 *
	 * @param {CipherProcessor} cipher A block cipher instance.
	 * @param {Array<number>} iv The IV words.
	 */
	init(cipher, iv) {
		this._cipher = cipher;
		this._iv = iv;
	}

	/**
	 * @abstract
	 * Processes the data block at offset.
	 *
	 * @param {Array<number>} words The data words to operate on.
	 * @param {number} offset The offset where the block starts.
	 *
	 * @example
	 *
	 *     mode.processBlock(data.words, offset);
	 */
	processBlock(words, offset) {}
}

/** @typedef {function(CipherProcessor, Array<number>): ModeProcessor} ModeCreator */ export var ModeCreator;
