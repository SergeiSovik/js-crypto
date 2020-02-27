/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Cipher, ENC_XFORM_MODE, DEC_XFORM_MODE, CipherHelper, StreamCipherProcessor } from "./cipher-core.js";
import { Dictionary } from "./../../../include/type.js"

/**
 * Rabbit stream cipher algorithm.
 */
class ClassCipherRabbit extends Cipher {
	constructor() {
		super();

		this.ivSize = 64/32;
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
	 *     var cipher = CipherRabbit.createEncryptor(keyWordArray, { 'iv': ivWordArray });
	 */
	createEncryptor(key, cfg) {
		return new CipherRabbitProcessor(ENC_XFORM_MODE, key, cfg);
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
	 *     var cipher = CipherRabbit.createDecryptor(keyWordArray, { 'iv': ivWordArray });
	 */
	createDecryptor(key, cfg) {
		return new CipherRabbitProcessor(DEC_XFORM_MODE, key, cfg);
	}
}

export const CipherRabbit = new ClassCipherRabbit();

// Reusable objects
let S  = [];
let C_ = [];
let G  = [];

/**
 * Rabbit stream cipher algorithm
 */
class CipherRabbitProcessor extends StreamCipherProcessor {
	/**
	 * @param {number} xformMode Either the encryption or decryption transormation mode constant.
	 * @param {WordArray} key The key.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 */
	constructor(xformMode, key, cfg) {
		super(xformMode, key, cfg);

		/** @type {Array<number>} */ this._X;
		/** @type {Array<number>} */ this._C;
		/** @type {number} */ this._b;
	}

	_doReset() {
		// Shortcuts
		let K = this._key.words;
		let iv = this.cfg.iv;

		// Swap endian
		for (let i = 0; i < 4; i++) {
			K[i] = (((K[i] << 8)  | (K[i] >>> 24)) & 0x00ff00ff) |
					(((K[i] << 24) | (K[i] >>> 8))  & 0xff00ff00);
		}

		// Generate initial state values
		let X = this._X = [
			K[0], (K[3] << 16) | (K[2] >>> 16),
			K[1], (K[0] << 16) | (K[3] >>> 16),
			K[2], (K[1] << 16) | (K[0] >>> 16),
			K[3], (K[2] << 16) | (K[1] >>> 16)
		];

		// Generate initial counter values
		let C = this._C = [
			(K[2] << 16) | (K[2] >>> 16), (K[0] & 0xffff0000) | (K[1] & 0x0000ffff),
			(K[3] << 16) | (K[3] >>> 16), (K[1] & 0xffff0000) | (K[2] & 0x0000ffff),
			(K[0] << 16) | (K[0] >>> 16), (K[2] & 0xffff0000) | (K[3] & 0x0000ffff),
			(K[1] << 16) | (K[1] >>> 16), (K[3] & 0xffff0000) | (K[0] & 0x0000ffff)
		];

		// Carry bit
		this._b = 0;

		// Iterate the system four times
		for (let i = 0; i < 4; i++) {
			this.nextState();
		}

		// Modify the counters
		for (let i = 0; i < 8; i++) {
			C[i] ^= X[(i + 4) & 7];
		}

		// IV setup
		if (iv) {
			// Shortcuts
			let IV = iv.words;
			let IV_0 = IV[0];
			let IV_1 = IV[1];

			// Generate four subvectors
			let i0 = (((IV_0 << 8) | (IV_0 >>> 24)) & 0x00ff00ff) | (((IV_0 << 24) | (IV_0 >>> 8)) & 0xff00ff00);
			let i2 = (((IV_1 << 8) | (IV_1 >>> 24)) & 0x00ff00ff) | (((IV_1 << 24) | (IV_1 >>> 8)) & 0xff00ff00);
			let i1 = (i0 >>> 16) | (i2 & 0xffff0000);
			let i3 = (i2 << 16)  | (i0 & 0x0000ffff);

			// Modify counter values
			C[0] ^= i0;
			C[1] ^= i1;
			C[2] ^= i2;
			C[3] ^= i3;
			C[4] ^= i0;
			C[5] ^= i1;
			C[6] ^= i2;
			C[7] ^= i3;

			// Iterate the system four times
			for (let i = 0; i < 4; i++) {
				this.nextState();
			}
		}
	}

	_doProcessBlock(M, offset) {
		// Shortcut
		let X = this._X;

		// Iterate the system
		this.nextState();

		// Generate four keystream words
		S[0] = X[0] ^ (X[5] >>> 16) ^ (X[3] << 16);
		S[1] = X[2] ^ (X[7] >>> 16) ^ (X[5] << 16);
		S[2] = X[4] ^ (X[1] >>> 16) ^ (X[7] << 16);
		S[3] = X[6] ^ (X[3] >>> 16) ^ (X[1] << 16);

		for (let i = 0; i < 4; i++) {
			// Swap endian
			S[i] = (((S[i] << 8)  | (S[i] >>> 24)) & 0x00ff00ff) |
					(((S[i] << 24) | (S[i] >>> 8))  & 0xff00ff00);

			// Encrypt
			M[offset + i] ^= S[i];
		}
	}

	/**
	 * @private
	 */
	nextState() {
		// Shortcuts
		let X = this._X;
		let C = this._C;
	
		// Save old counter values
		for (let i = 0; i < 8; i++) {
			C_[i] = C[i];
		}
	
		// Calculate new counter values
		C[0] = (C[0] + 0x4d34d34d + this._b) | 0;
		C[1] = (C[1] + 0xd34d34d3 + ((C[0] >>> 0) < (C_[0] >>> 0) ? 1 : 0)) | 0;
		C[2] = (C[2] + 0x34d34d34 + ((C[1] >>> 0) < (C_[1] >>> 0) ? 1 : 0)) | 0;
		C[3] = (C[3] + 0x4d34d34d + ((C[2] >>> 0) < (C_[2] >>> 0) ? 1 : 0)) | 0;
		C[4] = (C[4] + 0xd34d34d3 + ((C[3] >>> 0) < (C_[3] >>> 0) ? 1 : 0)) | 0;
		C[5] = (C[5] + 0x34d34d34 + ((C[4] >>> 0) < (C_[4] >>> 0) ? 1 : 0)) | 0;
		C[6] = (C[6] + 0x4d34d34d + ((C[5] >>> 0) < (C_[5] >>> 0) ? 1 : 0)) | 0;
		C[7] = (C[7] + 0xd34d34d3 + ((C[6] >>> 0) < (C_[6] >>> 0) ? 1 : 0)) | 0;
		this._b = (C[7] >>> 0) < (C_[7] >>> 0) ? 1 : 0;
	
		// Calculate the g-values
		for (let i = 0; i < 8; i++) {
			let gx = X[i] + C[i];
	
			// Construct high and low argument for squaring
			let ga = gx & 0xffff;
			let gb = gx >>> 16;
	
			// Calculate high and low result of squaring
			let gh = ((((ga * ga) >>> 17) + ga * gb) >>> 15) + gb * gb;
			let gl = (((gx & 0xffff0000) * gx) | 0) + (((gx & 0x0000ffff) * gx) | 0);
	
			// High XOR low
			G[i] = gh ^ gl;
		}
	
		// Calculate new state values
		X[0] = (G[0] + ((G[7] << 16) | (G[7] >>> 16)) + ((G[6] << 16) | (G[6] >>> 16))) | 0;
		X[1] = (G[1] + ((G[0] << 8)  | (G[0] >>> 24)) + G[7]) | 0;
		X[2] = (G[2] + ((G[1] << 16) | (G[1] >>> 16)) + ((G[0] << 16) | (G[0] >>> 16))) | 0;
		X[3] = (G[3] + ((G[2] << 8)  | (G[2] >>> 24)) + G[1]) | 0;
		X[4] = (G[4] + ((G[3] << 16) | (G[3] >>> 16)) + ((G[2] << 16) | (G[2] >>> 16))) | 0;
		X[5] = (G[5] + ((G[4] << 8)  | (G[4] >>> 24)) + G[3]) | 0;
		X[6] = (G[6] + ((G[5] << 16) | (G[5] >>> 16)) + ((G[4] << 16) | (G[4] >>> 16))) | 0;
		X[7] = (G[7] + ((G[6] << 8)  | (G[6] >>> 24)) + G[5]) | 0;
	}	
}

/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     let ciphertext = Rabbit.encrypt(message, key, cfg);
 *     let plaintext  = Rabbit.decrypt(ciphertext, key, cfg);
 */
export const Rabbit = new CipherHelper(CipherRabbit);
