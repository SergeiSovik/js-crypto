/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Hasher } from "./hasher.js"
import { HMAC } from "./hmac.js"

// Initialization and round constants tables
const H = platform.FixedInt32Array(8);
const K = platform.FixedInt32Array(64);

// Compute constants
{
	/**
	 * @param {number} n 
	 * @returns {boolean}
	 */
	function isPrime(n) {
		let sqrtN = Math.sqrt(n);
		for (let factor = 2; factor <= sqrtN; factor++) {
			if (!(n % factor)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * @param {number} n 
	 * @returns {number}
	 */
	function getFractionalBits(n) {
		return ((n - (n | 0)) * 0x100000000) | 0;
	}

	let n = 2;
	let nPrime = 0;
	while (nPrime < 64) {
		if (isPrime(n)) {
			if (nPrime < 8) {
				H[nPrime] = getFractionalBits(Math.pow(n, 1 / 2));
			}
			K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));

			nPrime++;
		}

		n++;
	}
}

// Reusable object
/** @type {Array<number>} */ let W = platform.FixedInt32Array(64);

/**
 * SHA-256 hash algorithm.
 */
export class HasherSHA256 extends Hasher {
	_doReset() {
		this._hash = new WordArray(H.slice(0));
	}

	/**
	 * @param {Array<number>} M
	 * @param {number} offset
	 */
	_doProcessBlock(M, offset) {
		// Shortcut
		let H = this._hash.words;

		// Working variables
		let a = H[0];
		let b = H[1];
		let c = H[2];
		let d = H[3];
		let e = H[4];
		let f = H[5];
		let g = H[6];
		let h = H[7];

		// Computation
		for (let i = 0; i < 64; i++) {
			if (i < 16) {
				W[i] = M[offset + i] | 0;
			} else {
				let gamma0x = W[i - 15];
				let gamma0  = ((gamma0x << 25) | (gamma0x >>> 7))  ^
								((gamma0x << 14) | (gamma0x >>> 18)) ^
								(gamma0x >>> 3);

				let gamma1x = W[i - 2];
				let gamma1  = ((gamma1x << 15) | (gamma1x >>> 17)) ^
								((gamma1x << 13) | (gamma1x >>> 19)) ^
								(gamma1x >>> 10);

				W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
			}

			let ch  = (e & f) ^ (~e & g);
			let maj = (a & b) ^ (a & c) ^ (b & c);

			let sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
			let sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7)  | (e >>> 25));

			let t1 = h + sigma1 + ch + K[i] + W[i];
			let t2 = sigma0 + maj;

			h = g;
			g = f;
			f = e;
			e = (d + t1) | 0;
			d = c;
			c = b;
			b = a;
			a = (t1 + t2) | 0;
		}

		// Intermediate hash value
		H[0] = (H[0] + a) | 0;
		H[1] = (H[1] + b) | 0;
		H[2] = (H[2] + c) | 0;
		H[3] = (H[3] + d) | 0;
		H[4] = (H[4] + e) | 0;
		H[5] = (H[5] + f) | 0;
		H[6] = (H[6] + g) | 0;
		H[7] = (H[7] + h) | 0;
	}

	/**
	 * @returns {WordArray}
	 */
	_doFinalize() {
		// Shortcuts
		let data = this._data;
		let dataWords = data.words;

		let nBitsTotal = this._nDataBytes * 8;
		let nBitsLeft = data.sigBytes * 8;

		// Add padding
		dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
		dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
		dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
		data.sigBytes = dataWords.length * 4;

		// Hash final blocks
		this._process();

		// Return final computed hash
		return this._hash;
	}
}

const _SHA256 = new HasherSHA256();

/**
 * Shortcut function to the hasher's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 *
 * @return {WordArray} The hash.
 *
 * @example
 *
 *     let hash = SHA256('message');
 *     let hash = SHA256(wordArray);
 */
export function SHA256(message) {
	return _SHA256.init().finalize(message);
}

/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 * @param {WordArray|string} key The secret key.
 *
 * @return {WordArray} The HMAC.
 *
 * @example
 *
 *     let hmac = HmacSHA256(message, key);
 */
export function HmacSHA256(message, key) {
	return new HMAC(_SHA256, key).finalize(message);
}

