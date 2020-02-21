/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { ModeProcessor, Mode } from "./mode.js"
import { BlockCipherProcessor } from "./cipher-core.js";

/**
 * Cipher Block Chaining mode.
 */
export class ModeCBC extends Mode {
	/**
	 * Creates this mode for encryption.
	 *
	 * @param {BlockCipherProcessor} cipher A block cipher instance.
	 * @param {Array<number>} iv The IV words.
	 * 
	 * @returns {ModeProcessor}
	 */
	createEncryptor(cipher, iv) {
		return new ModeCBCEncryptor(cipher, iv);
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
		return new ModeCBCDecryptor(cipher, iv);
	}
}

export const CBC = new ModeCBC();

/**
 * CBC encryptor.
 */
class ModeCBCEncryptor extends ModeProcessor {
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
		let cipher = this._cipher;
		let blockSize = cipher.blockSize;

		// XOR and encrypt
		xorBlock(this, words, offset, blockSize);
		cipher.encryptBlock(words, offset);

		// Remember this block to use with next block
		this._prevBlock = words.slice(offset, offset + blockSize);
	}
}

/**
 * CBC decryptor.
 */
class ModeCBCDecryptor extends ModeProcessor {
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
		// Shortcuts
		let cipher = this._cipher;
		let blockSize = cipher.blockSize;

		// Remember this block to use with next block
		let thisBlock = words.slice(offset, offset + blockSize);

		// Decrypt and XOR
		cipher.decryptBlock(words, offset);
		xorBlock(this, words, offset, blockSize);

		// This block becomes the previous block
		this._prevBlock = thisBlock;
	}
}

/**
 * @param {ModeProcessor} target
 * @param {Array<number>} words 
 * @param {number} offset 
 * @param {number} blockSize 
 */
function xorBlock(target, words, offset, blockSize) {
	// Shortcut
	let iv = target._iv;

	// Choose mixing block
	/** @type {Array<number>} */ let block;
	if (iv) {
		block = iv;

		// Remove IV for subsequent blocks
		target._iv = undefined;
	} else {
		block = target._prevBlock;
	}

	// XOR blocks
	for (let i = 0; i < blockSize; i++) {
		words[offset + i] ^= block[i];
	}
}
