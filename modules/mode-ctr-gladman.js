/**
 * Original work Copyright (c) Jan Hruby <jhruby.web@gmail.com>
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { ModeProcessor, Mode } from "./mode.js"
import { BlockCipherProcessor } from "./cipher-core.js"

/**
 * Counter block mode compatible with Dr Brian Gladman fileenc.c
 */
export class ModeCTRGladman extends Mode {
	/**
	 * Creates this mode for encryption.
	 *
	 * @param {BlockCipherProcessor} cipher A block cipher instance.
	 * @param {Array<number>} iv The IV words.
	 * 
	 * @returns {ModeProcessor}
	 */
	createEncryptor(cipher, iv) {
		return new ModeCTRGladmanProcessor(cipher, iv);
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
		return new ModeCTRGladmanProcessor(cipher, iv);
	}
}

export const CTRGladman = new ModeCTRGladman();

/**
 * CTRGladman encryptor.
 */
class ModeCTRGladmanProcessor extends ModeProcessor {
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
		
		incCounter(counter);
		
		let keystream = counter.slice(0);
		cipher.encryptBlock(keystream, 0);

		// Encrypt
		for (let i = 0; i < blockSize; i++) {
			words[offset + i] ^= keystream[i];
		}
	}
}

/**
 * @param {number} word 
 * @returns {number}
 */
function incWord(word) {	
	if (((word >> 24) & 0xff) === 0xff) { //overflow
		let b1 = (word >> 16)&0xff;
		let b2 = (word >> 8)&0xff;
		let b3 = word & 0xff;

		if (b1 === 0xff) { // overflow b1
			b1 = 0;
			if (b2 === 0xff) {
				b2 = 0;
				if (b3 === 0xff) {
					b3 = 0;
				} else {
					++b3;
				}
			} else {
				++b2;
			}
		} else {
			++b1;
		}

		word = 0;	  	  
		word += (b1 << 16);
		word += (b2 << 8);
		word += b3;	  
	} else {
		word += (0x01 << 24);
	}
	return word;
}

/**
 * @param {Array<number>} counter 
 * @returns {Array<number>}
 */
function incCounter(counter) {
	if ((counter[0] = incWord(counter[0])) === 0) {
		// encr_data in fileenc.c from  Dr Brian Gladman's counts only with DWORD j < 8
		counter[1] = incWord(counter[1]);
	}
	return counter;
}
