/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { ModeProcessor, Mode } from "./mode.js"
import { BlockCipherProcessor } from "./cipher-core.js";

/**
 * Electronic Codebook block mode.
 */
export class ModeECB extends Mode {
	/**
	 * Creates this mode for encryption.
	 *
	 * @param {BlockCipherProcessor} cipher A block cipher instance.
	 * @param {Array<number>} iv The IV words.
	 * 
	 * @returns {ModeProcessor}
	 */
	createEncryptor(cipher, iv) {
		return new ModeECBEncryptor(cipher, iv);
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
		return new ModeECBDecryptor(cipher, iv);
	}
}

export const ECB = new ModeECB();

/**
 * ECB encryptor.
 */
class ModeECBEncryptor extends ModeProcessor {
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
		this._cipher.encryptBlock(words, offset);
	}
}

/**
 * ECB decryptor.
 */
class ModeECBDecryptor extends ModeProcessor {
	/**
	 * Processes the data block at offset.
	 *
	 * @param {Array} words The data words to operate on.
	 * @param {number} offset The offset where the block starts.
	 *
	 * @example
	 *
	 *     mode.processBlock(data.words, offset);
	 */
	processBlock(words, offset) {
		this._cipher.decryptBlock(words, offset);
	}
}
