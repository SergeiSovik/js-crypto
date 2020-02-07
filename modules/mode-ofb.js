/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { ModeProcessor, Mode } from "./mode.js"
import { CipherProcessor } from "./cipher-processor.js";

/**
 * Output Feedback block mode.
 */
export class ModeOFB extends Mode {
	/**
	 * Creates this mode for encryption.
	 *
	 * @param {CipherProcessor} cipher A block cipher instance.
	 * @param {Array<number>} iv The IV words.
	 * 
	 * @returns {ModeProcessor}
	 */
	createEncryptor(cipher, iv) {
		return new ModeOFBProcessor(cipher, iv);
	}

	/**
	 * Creates this mode for encryption.
	 *
	 * @param {CipherProcessor} cipher A block cipher instance.
	 * @param {Array<number>} iv The IV words.
	 * 
	 * @returns {ModeProcessor}
	 */
	createDecryptor(cipher, iv) {
		return new ModeOFBProcessor(cipher, iv);
	}
}

export const OFB = new ModeOFB();

/**
 * OFB encryptor.
 */
class ModeOFBProcessor extends ModeProcessor {
	/**
	 * @param {CipherProcessor} cipher A block cipher instance.
	 * @param {Array<number>} iv The IV words.
	 */
	constructor(cipher, iv) {
		super(cipher, iv);

		/** @type {Array<number>} */ this._keystream;
	}

	/**
	 * Processes the data block at offset.
	 *
	 * @param {Array<number>} words The data words to operate on.
	 * @param {number} offset The offset where the block starts.
	 *
	 * @example
	 *
	 *     mode.processBlock(data.words, offset);
	 */
	processBlock(words, offset) {
		// Shortcuts
		let cipher = this._cipher
		let blockSize = cipher.blockSize;
		let iv = this._iv;
		let keystream = this._keystream;

		// Generate keystream
		if (iv) {
			keystream = this._keystream = iv.slice(0);

			// Remove IV for subsequent blocks
			this._iv = undefined;
		}
		cipher.encryptBlock(keystream, 0);

		// Encrypt
		for (let i = 0; i < blockSize; i++) {
			words[offset + i] ^= keystream[i];
		}
	}
}
