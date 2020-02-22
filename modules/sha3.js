/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 * 
 * FIXED SHA3 (FIPS-202 Spec) Padding by Sergio Rando 
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Hasher } from "./hasher.js"
import { HMAC } from "./hmac.js"

// Constants tables
let RHO_OFFSETS = platform.FixedInt32Array([
	0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
]);

let PI_INDEXES  = platform.FixedInt32Array([
	0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4
]);

let ROUND_CONSTANTS = platform.FixedInt32Array([
	0x00000000, 0x00000001, 0x00000000, 0x00008082, 0x80000000, 0x0000808a, 0x80000000, 0x80008000,
	0x00000000, 0x0000808b, 0x00000000, 0x80000001, 0x80000000, 0x80008081, 0x80000000, 0x00008009,
	0x00000000, 0x0000008a, 0x00000000, 0x00000088, 0x00000000, 0x80008009, 0x00000000, 0x8000000a,
	0x00000000, 0x8000808b, 0x80000000, 0x0000008b, 0x80000000, 0x00008089, 0x80000000, 0x00008003,
	0x80000000, 0x00008002, 0x80000000, 0x00000080, 0x00000000, 0x0000800a, 0x80000000, 0x8000000a,
	0x80000000, 0x80008081, 0x80000000, 0x00008080, 0x00000000, 0x80000001, 0x80000000, 0x80008008
]);

// Compute Constants
/*
	// Compute rho offset constants
	let x = 1, y = 0;
	for (let t = 0; t < 24; t++) {
		RHO_OFFSETS[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64;

		let newX = y % 5;
		let newY = (2 * x + 3 * y) % 5;
		x = newX;
		y = newY;
	}

	// Compute pi index constants
	for (let x = 0; x < 5; x++) {
		for (let y = 0; y < 5; y++) {
			PI_INDEXES[x + 5 * y] = y + ((2 * x + 3 * y) % 5) * 5;
		}
	}

	// Compute round constants
	let LFSR = 0x01;
	for (let i = 0; i < 24; i++) {
		let roundConstantMsw = 0;
		let roundConstantLsw = 0;

		for (let j = 0; j < 7; j++) {
			if (LFSR & 0x01) {
				let bitPosition = (1 << j) - 1;
				if (bitPosition < 32) {
					roundConstantLsw ^= 1 << bitPosition;
				} else { // if (bitPosition >= 32)
					roundConstantMsw ^= 1 << (bitPosition - 32);
				}
			}

			// Compute next LFSR
			if (LFSR & 0x80) {
				// Primitive polynomial over GF(2): x^8 + x^6 + x^5 + x^4 + 1
				LFSR = (LFSR << 1) ^ 0x71;
			} else {
				LFSR <<= 1;
			}
		}

		ROUND_CONSTANTS[i * 2] = roundConstantMsw;
		ROUND_CONSTANTS[i * 2 + 1] = roundConstantLsw;
	}
*/

// Reusable objects for temporary values
let T = platform.FixedInt32Array(50);

const acceptOutputLength = [224, 256, 384, 512];

/**
 * Configuration options.
 *
 * @property {number} outputLength
 *   The desired number of bits in the output hash.
 *   Only values permitted are: 224, 256, 384, 512.
 *   Default: 512
 */
class ConfigSHA3 {
	/**
	 * @param {*=} cfg (Optional) The configuration options.
	 */
	constructor(cfg) {
		/** @type {number} */ this.outputLength = 512;

		let outputLength = cfg && cfg['outputLength'] || undefined;
		if (outputLength !== undefined && typeof outputLength === 'number' && outputLength in acceptOutputLength)
			this.outputLength = outputLength;
	}
}

/**
 * SHA-3 hash algorithm.
 */
export class HasherSHA3 extends Hasher {
	/**
	 * @param {*=} cfg (Optional) Configuration options for SHA3
	 */
	constructor(cfg) {
		super();

		/** @type {ConfigSHA3} */ this.cfg;
		/** @type {Array<number>} */ this._state;

		this.init(cfg);
	}

	/**
	 * @override
	 * @param {*=} cfg (Optional) Configuration options for SHA3
	 */
	init(cfg) {
		this.updateConfig(cfg);

		super.init();
		
		return this;
	}

	/**
	 * @param {*=} cfg (Optional) Configuration options for SHA3
	 */
	updateConfig(cfg) {
		// Apply config defaults
		this.cfg = new ConfigSHA3(cfg);
	}

	_doReset() {
		let state = this._state = []
		for (let i = 0; i < 25; i++) {
			state[i * 2] = 0;
			state[i * 2 + 1] = 0;
		}

		this.blockSize = (1600 - 2 * this.cfg.outputLength) / 32;
	}

	/**
	 * @param {Array<number>} M
	 * @param {number} offset
	 */
	_doProcessBlock(M, offset) {
		// Shortcuts
		let state = this._state;
		let nBlockSizeLanes = this.blockSize / 2;

		// Absorb
		for (let i = 0; i < nBlockSizeLanes; i++) {
			// Shortcuts
			let M2i  = M[offset + 2 * i];
			let M2i1 = M[offset + 2 * i + 1];

			// Swap endian
			M2i = (
				(((M2i << 8)  | (M2i >>> 24)) & 0x00ff00ff) |
				(((M2i << 24) | (M2i >>> 8))  & 0xff00ff00)
			);
			M2i1 = (
				(((M2i1 << 8)  | (M2i1 >>> 24)) & 0x00ff00ff) |
				(((M2i1 << 24) | (M2i1 >>> 8))  & 0xff00ff00)
			);

			// Absorb message into state
			state[i * 2]		^= M2i1;
			state[i * 2 + 1]	^= M2i;
		}

		// Rounds
		for (let round = 0; round < 24; round++) {
			// Theta
			for (let x = 0; x < 5; x++) {
				// Mix column lanes
				let tMsw = 0, tLsw = 0;
				for (let y = 0; y < 5; y++) {
					let index = x + 5 * y;
					tMsw ^= state[index * 2];
					tLsw ^= state[index * 2 + 1];
				}

				// Temporary values
				T[x * 2] = tMsw;
				T[x * 2 + 1]  = tLsw;
			}
			for (let x = 0; x < 5; x++) {
				// Shortcuts
				let index4 = (x + 4) % 5;
				let index1 = (x + 1) % 5;
				let Tx1Msw = T[index1 * 2];
				let Tx1Lsw = T[index1 * 2 + 1];

				// Mix surrounding columns
				let tMsw = T[index4 * 2] ^ ((Tx1Msw << 1) | (Tx1Lsw >>> 31));
				let tLsw = T[index4 * 2 + 1] ^ ((Tx1Lsw << 1) | (Tx1Msw >>> 31));
				for (let y = 0; y < 5; y++) {
					let index = x + 5 * y;
					state[index * 2] ^= tMsw;
					state[index * 2 + 1]  ^= tLsw;
				}
			}

			// Rho Pi
			for (let laneIndex = 1; laneIndex < 25; laneIndex++) {
				// Shortcuts
				let laneMsw = state[laneIndex * 2];
				let laneLsw = state[laneIndex * 2 + 1];
				let rhoOffset = RHO_OFFSETS[laneIndex];

				// Rotate lanes
				/** @type {number} */ let tMsw;
				/** @type {number} */ let tLsw;
				if (rhoOffset < 32) {
					tMsw = (laneMsw << rhoOffset) | (laneLsw >>> (32 - rhoOffset));
					tLsw = (laneLsw << rhoOffset) | (laneMsw >>> (32 - rhoOffset));
				} else /* if (rhoOffset >= 32) */ {
					tMsw = (laneLsw << (rhoOffset - 32)) | (laneMsw >>> (64 - rhoOffset));
					tLsw = (laneMsw << (rhoOffset - 32)) | (laneLsw >>> (64 - rhoOffset));
				}

				// Transpose lanes
				let index = PI_INDEXES[laneIndex];
				T[index * 2] = tMsw;
				T[index * 2 + 1]  = tLsw;
			}

			// Rho pi at x = y = 0
			T[0] = state[0];
			T[1] = state[1];

			// Chi
			for (let x = 0; x < 5; x++) {
				for (let y = 0; y < 5; y++) {
					// Shortcuts
					let laneIndex = x + 5 * y;
					let index1 = ((x + 1) % 5) + 5 * y;
					let index2 = ((x + 2) % 5) + 5 * y;

					// Mix rows
					state[laneIndex * 2] = T[laneIndex * 2] ^ (~T[index1 * 2] & T[index2 * 2]);
					state[laneIndex * 2 + 1] = T[laneIndex * 2 + 1] ^ (~T[index1 * 2 + 1]  & T[index2 * 2 + 1]);
				}
			}

			// Iota
			state[0] ^= ROUND_CONSTANTS[round * 2];
			state[1] ^= ROUND_CONSTANTS[round * 2 + 1];
		}
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
		let blockSizeBits = this.blockSize * 32;

		// Add padding
		dataWords[nBitsLeft >>> 5] |= 0x6 << (24 - nBitsLeft % 32);
		dataWords[((Math.ceil((nBitsLeft + 1) / blockSizeBits) * blockSizeBits) >>> 5) - 1] |= 0x80;
		data.sigBytes = dataWords.length * 4;

		// Hash final blocks
		this._process();

		// Shortcuts
		let state = this._state;
		let outputLengthBytes = this.cfg.outputLength / 8;
		let outputLengthLanes = outputLengthBytes / 8;

		// Squeeze
		let hashWords = [];
		for (let i = 0; i < outputLengthLanes; i++) {
			// Shortcuts
			let laneMsw = state[i * 2];
			let laneLsw = state[i * 2 + 1];

			// Swap endian
			laneMsw = (
				(((laneMsw << 8)  | (laneMsw >>> 24)) & 0x00ff00ff) |
				(((laneMsw << 24) | (laneMsw >>> 8))  & 0xff00ff00)
			);
			laneLsw = (
				(((laneLsw << 8)  | (laneLsw >>> 24)) & 0x00ff00ff) |
				(((laneLsw << 24) | (laneLsw >>> 8))  & 0xff00ff00)
			);

			// Squeeze state to retrieve hash
			hashWords.push(laneLsw);
			hashWords.push(laneMsw);
		}

		// Return final computed hash
		return new WordArray(hashWords, outputLengthBytes);
	}
}

const _SHA3 = new HasherSHA3();

/**
 * Shortcut function to the hasher's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 * @param {*=} cfg
 *
 * @return {WordArray} The hash.
 *
 * @example
 *
 *     let hash = SHA3('message');
 *     let hash = SHA3(wordArray);
 */
export function SHA3(message, cfg) {
	return _SHA3.init(cfg).finalize(message);
}

/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 * @param {WordArray|string} key The secret key.
 * @param {*=} cfg
 *
 * @return {WordArray} The HMAC.
 *
 * @example
 *
 *     let hmac = HmacSHA3(message, key);
 */
export function HmacSHA3(message, key, cfg) {
	return new HMAC(_SHA3.init(cfg), key).finalize(message);
}
