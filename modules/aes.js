/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Cipher, ENC_XFORM_MODE, DEC_XFORM_MODE, CipherHelper, BlockCipherProcessor } from "./cipher-core.js";

// Lookup tables
/** @type {Array<number>} */ let SBOX = platform.FixedInt32Array(256);
/** @type {Array<number>} */ let INV_SBOX = platform.FixedInt32Array(256);
/** @type {Array<number>} */ let SUB_MIX_0 = platform.FixedInt32Array(256);
/** @type {Array<number>} */ let SUB_MIX_1 = platform.FixedInt32Array(256);
/** @type {Array<number>} */ let SUB_MIX_2 = platform.FixedInt32Array(256);
/** @type {Array<number>} */ let SUB_MIX_3 = platform.FixedInt32Array(256);
/** @type {Array<number>} */ let INV_SUB_MIX_0 = platform.FixedInt32Array(256);
/** @type {Array<number>} */ let INV_SUB_MIX_1 = platform.FixedInt32Array(256);
/** @type {Array<number>} */ let INV_SUB_MIX_2 = platform.FixedInt32Array(256);
/** @type {Array<number>} */ let INV_SUB_MIX_3 = platform.FixedInt32Array(256);

// Compute lookup tables
{
	// Compute double table
	let d = [];
	for (let i = 0; i < 256; i++) {
		if (i < 128) {
			d[i] = i << 1;
		} else {
			d[i] = (i << 1) ^ 0x11b;
		}
	}

	// Walk GF(2^8)
	let x = 0;
	let xi = 0;
	for (let i = 0; i < 256; i++) {
		// Compute sbox
		let sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4);
		sx = (sx >>> 8) ^ (sx & 0xff) ^ 0x63;
		SBOX[x] = sx;
		INV_SBOX[sx] = x;

		// Compute multiplication
		let x2 = d[x];
		let x4 = d[x2];
		let x8 = d[x4];

		// Compute sub bytes, mix columns tables
		let t = (d[sx] * 0x101) ^ (sx * 0x1010100);
		SUB_MIX_0[x] = (t << 24) | (t >>> 8);
		SUB_MIX_1[x] = (t << 16) | (t >>> 16);
		SUB_MIX_2[x] = (t << 8)  | (t >>> 24);
		SUB_MIX_3[x] = t;

		// Compute inv sub bytes, inv mix columns tables
		t = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100);
		INV_SUB_MIX_0[sx] = (t << 24) | (t >>> 8);
		INV_SUB_MIX_1[sx] = (t << 16) | (t >>> 16);
		INV_SUB_MIX_2[sx] = (t << 8)  | (t >>> 24);
		INV_SUB_MIX_3[sx] = t;

		// Compute next counter
		if (!x) {
			x = xi = 1;
		} else {
			x = x2 ^ d[d[d[x8 ^ x2]]];
			xi ^= d[d[xi]];
		}
	}
}

// Precomputed Rcon lookup
let RCON = platform.FixedInt32Array([0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]);

/**
 * AES block cipher algorithm.
 */
class ClassCipherAES extends Cipher {
	constructor() {
		super();

		this.keySize = 256/32;
	}

	/**
	 * Creates this cipher in encryption mode.
	 *
	 * @param {WordArray} key The key.
	 * @param {Object<string,*>=} cfg (Optional) The configuration options to use for this operation.
	 *
	 * @return {BlockCipherProcessor} A cipher instance.
	 *
	 * @example
	 *
	 *     var cipher = CipherAES.createEncryptor(keyWordArray, { 'iv': ivWordArray });
	 */
	createEncryptor(key, cfg) {
		return new CipherAESProcessor(ENC_XFORM_MODE, key, cfg);
	}

	/**
	 * Creates this cipher in decryption mode.
	 *
	 * @param {WordArray} key The key.
	 * @param {Object<string,*>=} cfg (Optional) The configuration options to use for this operation.
	 *
	 * @return {BlockCipherProcessor} A cipher instance.
	 *
	 * @example
	 *
	 *     var cipher = CipherAES.createDecryptor(keyWordArray, { 'iv': ivWordArray });
	 */
	createDecryptor(key, cfg) {
		return new CipherAESProcessor(DEC_XFORM_MODE, key, cfg);
	}
}

export const CipherAES = new ClassCipherAES();

class CipherAESProcessor extends BlockCipherProcessor {
	/**
	 * @param {number} xformMode Either the encryption or decryption transormation mode constant.
	 * @param {WordArray} key The key.
	 * @param {Object<string,*>=} cfg (Optional) The configuration options to use for this operation.
	 */
	constructor(xformMode, key, cfg) {
		super(xformMode, key, cfg);

		/** @type {number} */ this._nRounds;
		/** @type {Array<number>} */ this._keySchedule;
		/** @type {Array<number>} */ this._invKeySchedule;
	}

	_doReset() {
		// Shortcuts
		let key = this._key;
		let keyWords = key.words;
		let keySize = key.sigBytes / 4;

		// Compute number of rounds
		let nRounds = this._nRounds = keySize + 6

		// Compute number of key schedule rows
		let ksRows = (nRounds + 1) * 4;

		// Compute key schedule
		let keySchedule = this._keySchedule = [];
		for (let ksRow = 0; ksRow < ksRows; ksRow++) {
			if (ksRow < keySize) {
				keySchedule[ksRow] = keyWords[ksRow];
			} else {
				let t = keySchedule[ksRow - 1];

				if (!(ksRow % keySize)) {
					// Rot word
					t = (t << 8) | (t >>> 24);

					// Sub word
					t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];

					// Mix Rcon
					t ^= RCON[(ksRow / keySize) | 0] << 24;
				} else if (keySize > 6 && ksRow % keySize == 4) {
					// Sub word
					t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];
				}

				keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t;
			}
		}

		// Compute inv key schedule
		let invKeySchedule = this._invKeySchedule = [];
		for (let invKsRow = 0; invKsRow < ksRows; invKsRow++) {
			let ksRow = ksRows - invKsRow;

			/** @type {number} */ let t;
			if (invKsRow % 4) {
				t = keySchedule[ksRow];
			} else {
				t = keySchedule[ksRow - 4];
			}

			if (invKsRow < 4 || ksRow <= 4) {
				invKeySchedule[invKsRow] = t;
			} else {
				invKeySchedule[invKsRow] = INV_SUB_MIX_0[SBOX[t >>> 24]] ^ INV_SUB_MIX_1[SBOX[(t >>> 16) & 0xff]] ^
					INV_SUB_MIX_2[SBOX[(t >>> 8) & 0xff]] ^ INV_SUB_MIX_3[SBOX[t & 0xff]];
			}
		}
	}

	/**
	 * @param {Array<number>} M 
	 * @param {number} offset 
	 */
	encryptBlock(M, offset) {
		this._doCryptBlock(M, offset, this._keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX);
	}

	/**
	 * @param {Array<number>} M 
	 * @param {number} offset 
	 */
	decryptBlock(M, offset) {
		// Swap 2nd and 4th rows
		let t = M[offset + 1];
		M[offset + 1] = M[offset + 3];
		M[offset + 3] = t;

		this._doCryptBlock(M, offset, this._invKeySchedule, INV_SUB_MIX_0, INV_SUB_MIX_1, INV_SUB_MIX_2, INV_SUB_MIX_3, INV_SBOX);

		// Inv swap 2nd and 4th rows
		t = M[offset + 1];
		M[offset + 1] = M[offset + 3];
		M[offset + 3] = t;
	}

	/**
	 * @param {Array<number>} M 
	 * @param {number} offset 
	 * @param {Array<number>} keySchedule 
	 * @param {Array<number>} SUB_MIX_0 
	 * @param {Array<number>} SUB_MIX_1 
	 * @param {Array<number>} SUB_MIX_2 
	 * @param {Array<number>} SUB_MIX_3 
	 * @param {Array<number>} SBOX 
	 */
	_doCryptBlock(M, offset, keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX) {
		// Shortcut
		let nRounds = this._nRounds;

		// Get input, add round key
		let s0 = M[offset]     ^ keySchedule[0];
		let s1 = M[offset + 1] ^ keySchedule[1];
		let s2 = M[offset + 2] ^ keySchedule[2];
		let s3 = M[offset + 3] ^ keySchedule[3];

		// Key schedule row counter
		let ksRow = 4;

		// Rounds
		for (let round = 1; round < nRounds; round++) {
			// Shift rows, sub bytes, mix columns, add round key
			let t0 = SUB_MIX_0[s0 >>> 24] ^ SUB_MIX_1[(s1 >>> 16) & 0xff] ^ SUB_MIX_2[(s2 >>> 8) & 0xff] ^ SUB_MIX_3[s3 & 0xff] ^ keySchedule[ksRow++];
			let t1 = SUB_MIX_0[s1 >>> 24] ^ SUB_MIX_1[(s2 >>> 16) & 0xff] ^ SUB_MIX_2[(s3 >>> 8) & 0xff] ^ SUB_MIX_3[s0 & 0xff] ^ keySchedule[ksRow++];
			let t2 = SUB_MIX_0[s2 >>> 24] ^ SUB_MIX_1[(s3 >>> 16) & 0xff] ^ SUB_MIX_2[(s0 >>> 8) & 0xff] ^ SUB_MIX_3[s1 & 0xff] ^ keySchedule[ksRow++];
			let t3 = SUB_MIX_0[s3 >>> 24] ^ SUB_MIX_1[(s0 >>> 16) & 0xff] ^ SUB_MIX_2[(s1 >>> 8) & 0xff] ^ SUB_MIX_3[s2 & 0xff] ^ keySchedule[ksRow++];

			// Update state
			s0 = t0;
			s1 = t1;
			s2 = t2;
			s3 = t3;
		}

		// Shift rows, sub bytes, add round key
		let t0 = ((SBOX[s0 >>> 24] << 24) | (SBOX[(s1 >>> 16) & 0xff] << 16) | (SBOX[(s2 >>> 8) & 0xff] << 8) | SBOX[s3 & 0xff]) ^ keySchedule[ksRow++];
		let t1 = ((SBOX[s1 >>> 24] << 24) | (SBOX[(s2 >>> 16) & 0xff] << 16) | (SBOX[(s3 >>> 8) & 0xff] << 8) | SBOX[s0 & 0xff]) ^ keySchedule[ksRow++];
		let t2 = ((SBOX[s2 >>> 24] << 24) | (SBOX[(s3 >>> 16) & 0xff] << 16) | (SBOX[(s0 >>> 8) & 0xff] << 8) | SBOX[s1 & 0xff]) ^ keySchedule[ksRow++];
		let t3 = ((SBOX[s3 >>> 24] << 24) | (SBOX[(s0 >>> 16) & 0xff] << 16) | (SBOX[(s1 >>> 8) & 0xff] << 8) | SBOX[s2 & 0xff]) ^ keySchedule[ksRow++];

		// Set output
		M[offset]     = t0;
		M[offset + 1] = t1;
		M[offset + 2] = t2;
		M[offset + 3] = t3;
	}
}

/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     let ciphertext = AES.encrypt(message, key, cfg);
 *     let plaintext  = AES.decrypt(ciphertext, key, cfg);
 */
export const AES = new CipherHelper(CipherAES);
