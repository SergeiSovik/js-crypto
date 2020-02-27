/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { ModeProcessor, Mode } from "./mode.js"
import { BlockCipherProcessor } from "./cipher-core"

/**
 * Counter block mode.
 */
export class ModeCTR extends Mode {
	/**
	 * Creates this mode for encryption.
	 *
	 * @param {BlockCipherProcessor} cipher A block cipher instance.
	 * @param {Array<number>} iv The IV words.
	 * 
	 * @returns {ModeProcessor}
	 */
	createEncryptor(cipher, iv) {
		return new ModeCTRProcessor(cipher, iv);
	}

	/**
	 * Creates this mode for encryption.
	 *
	 * @param {BlockCipherProcessor} cipher A block cipher instance.
	 * @param {Array<number>} iv The IV words.
	 * 
	 * @returns {ModeProcessor}
	 */
	createDecryptor(cipher, iv) {
		return new ModeCTRProcessor(cipher, iv);
	}
}

export const CTR = new ModeCTR();

/**
 * CTR encryptor.
 */
class ModeCTRProcessor extends ModeProcessor {
	/**
	 * @param {BlockCipherProcessor} cipher A block cipher instance.
	 * @param {Array<number>} iv The IV words.
	 */
	constructor(cipher, iv) {
		super(cipher, iv);

		/** @type {Array<number>} */ this._counter;
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
		let counter = this._counter;

		// Generate keystream
		if (iv) {
			counter = this._counter = iv.slice(0);

			// Remove IV for subsequent blocks
			this._iv = undefined;
		}
		let keystream = counter.slice(0);
		cipher.encryptBlock(keystream, 0);

		// Increment counter
		counter[blockSize - 1] = (counter[blockSize - 1] + 1) | 0

		// Encrypt
		for (let i = 0; i < blockSize; i++) {
			words[offset + i] ^= keystream[i];
		}
	}
}
