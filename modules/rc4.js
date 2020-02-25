/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Cipher, ENC_XFORM_MODE, DEC_XFORM_MODE, CipherHelper, StreamCipherProcessor } from "./cipher-core.js";
import { Dictionary } from "./../../../include/type.js"

/**
 * RC4 stream cipher algorithm.
 */
class ClassCipherRC4 extends Cipher {
	constructor() {
		super();

		this.keySize = 256/32;
		this.ivSize = 0;
	}

	/**
	 * Creates this cipher in encryption mode.
	 *
	 * @param {WordArray} key The key.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 *
	 * @return {StreamCipherProcessor} A cipher instance.
	 *
	 * @example
	 *
	 *     var cipher = CipherRC4.createEncryptor(keyWordArray, { 'iv': ivWordArray });
	 */
	createEncryptor(key, cfg) {
		return new CipherRC4Processor(ENC_XFORM_MODE, key, cfg);
	}

	/**
	 * Creates this cipher in decryption mode.
	 *
	 * @param {WordArray} key The key.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 *
	 * @return {StreamCipherProcessor} A cipher instance.
	 *
	 * @example
	 *
	 *     var cipher = CipherRC4.createDecryptor(keyWordArray, { 'iv': ivWordArray });
	 */
	createDecryptor(key, cfg) {
		return new CipherRC4Processor(DEC_XFORM_MODE, key, cfg);
	}
}

export const CipherRC4 = new ClassCipherRC4();

/**
 * RC4 stream cipher algorithm.
 */
class CipherRC4Processor extends StreamCipherProcessor {
	/**
	 * @param {number} xformMode Either the encryption or decryption transormation mode constant.
	 * @param {WordArray} key The key.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 */
	constructor(xformMode, key, cfg) {
		super(xformMode, key, cfg);

		/** @type {Array<number>} */ this._S;
		/** @type {number} */ this._i;
		/** @type {number} */ this._j;
	}

	_doReset() {
		// Shortcuts
		let key = this._key;
		let keyWords = key.words;
		let keySigBytes = key.sigBytes;

		// Init sbox
		let S = this._S = [];
		for (let i = 0; i < 256; i++) {
			S[i] = i;
		}

		// Key setup
		for (let i = 0, j = 0; i < 256; i++) {
			let keyByteIndex = i % keySigBytes;
			let keyByte = (keyWords[keyByteIndex >>> 2] >>> (24 - (keyByteIndex % 4) * 8)) & 0xff;

			j = (j + S[i] + keyByte) % 256;

			// Swap
			let t = S[i];
			S[i] = S[j];
			S[j] = t;
		}

		// Counters
		this._i = this._j = 0;
	}

	_doProcessBlock(M, offset) {
		M[offset] ^= this.generateKeystreamWord();
	}

	/**
	 * @protected
	 */
	generateKeystreamWord() {
        // Shortcuts
        let S = this._S;
        let i = this._i;
        let j = this._j;

        // Generate keystream word
        let keystreamWord = 0;
        for (let n = 0; n < 4; n++) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;

            // Swap
            let t = S[i];
            S[i] = S[j];
            S[j] = t;

            keystreamWord |= S[(S[i] + S[j]) % 256] << (24 - n * 8);
        }

        // Update counters
        this._i = i;
        this._j = j;

        return keystreamWord;
    }
}

/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     let ciphertext = RC4.encrypt(message, key, cfg);
 *     let plaintext  = RC4.decrypt(ciphertext, key, cfg);
 */
export const RC4 = new CipherHelper(CipherRC4);

/**
 * RC4 Drop stream cipher algorithm.
 */
class ClassCipherRC4Drop extends ClassCipherRC4 {
	constructor() {
		super();
	}

	/**
	 * Creates this cipher in encryption mode.
	 *
	 * @param {WordArray} key The key.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 *
	 * @return {StreamCipherProcessor} A cipher instance.
	 *
	 * @example
	 *
	 *     var cipher = CipherRC4Drop.createEncryptor(keyWordArray, { 'iv': ivWordArray });
	 */
	createEncryptor(key, cfg) {
		return new CipherRC4DropProcessor(ENC_XFORM_MODE, key, cfg);
	}

	/**
	 * Creates this cipher in decryption mode.
	 *
	 * @param {WordArray} key The key.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 *
	 * @return {StreamCipherProcessor} A cipher instance.
	 *
	 * @example
	 *
	 *     var cipher = CipherRC4Drop.createDecryptor(keyWordArray, { 'iv': ivWordArray });
	 */
	createDecryptor(key, cfg) {
		return new CipherRC4DropProcessor(DEC_XFORM_MODE, key, cfg);
	}
}

export const CipherRC4Drop = new ClassCipherRC4Drop();

/**
 * Modified RC4 stream cipher algorithm.
 */
class CipherRC4DropProcessor extends CipherRC4Processor {
	/**
	 * @param {number} xformMode Either the encryption or decryption transormation mode constant.
	 * @param {WordArray} key The key.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 */
	constructor(xformMode, key, cfg) {
		super(xformMode, key, cfg);

		/** @type {number} */ this.drop = 192;

		let drop = cfg && cfg['drop'] || undefined; if (drop !== undefined && Number.isInteger(/** @type {number} */ ( drop ))) this.drop = /** @type {number} */ ( drop );
	}

	_doReset() {
		super._doReset();

		// Drop
		for (let i = this.drop; i > 0; i--) {
			this.generateKeystreamWord();
		}
	}
}

/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     let ciphertext = RC4Drop.encrypt(message, key, cfg);
 *     let plaintext  = RC4Drop.decrypt(ciphertext, key, cfg);
 */
export const RC4Drop = new CipherHelper(CipherRC4Drop);
