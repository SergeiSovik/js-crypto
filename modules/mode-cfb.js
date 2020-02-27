/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { ModeProcessor, Mode } from "./mode.js"
import { BlockCipherProcessor } from "./cipher-core.js"

/**
 * Cipher Feedback block mode.
 */
export class ModeCFB extends Mode {
	/**
	 * Creates this mode for encryption.
	 *
	 * @param {BlockCipherProcessor} cipher A block cipher instance.
	 * @param {Array<number>} iv The IV words.
	 * 
	 * @returns {ModeProcessor}
	 */
	createEncryptor(cipher, iv) {
		return new ModeCFBEncryptor(cipher, iv);
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
		return new ModeCFBDecryptor(cipher, iv);
	}
}

export const CFB = new ModeCFB();

/**
 * CFB encryptor.
 */
class ModeCFBEncryptor extends ModeProcessor {
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

		generateKeystreamAndEncrypt(this, words, offset, blockSize, cipher);

		// Remember this block to use with next block
		this._prevBlock = words.slice(offset, offset + blockSize);
	}
}

/**
 * CFB decryptor.
 */
class ModeCFBDecryptor extends ModeProcessor {
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

		generateKeystreamAndEncrypt(this, words, offset, blockSize, cipher);

		// This block becomes the previous block
		this._prevBlock = thisBlock;
	}
}

/**
 * @param {ModeProcessor} target 
 * @param {Array<number>} words 
 * @param {number} offset 
 * @param {number} blockSize 
 * @param {BlockCipherProcessor} cipher 
 */
function generateKeystreamAndEncrypt(target, words, offset, blockSize, cipher) {
	// Shortcut
	let iv = target._iv;

	// Generate keystream
	/** @type {Array<number>} */ let keystream;
	if (iv) {
		keystream = iv.slice(0);

		// Remove IV for subsequent blocks
		target._iv = undefined;
	} else {
		keystream = target._prevBlock;
	}
	cipher.encryptBlock(keystream, 0);

	// Encrypt
	for (let i = 0; i < blockSize; i++) {
		words[offset + i] ^= keystream[i];
	}
}
