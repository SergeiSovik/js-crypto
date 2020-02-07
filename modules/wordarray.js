/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 *
 * THIS IS FIX of 'core.js' to fix Hmac issue.
 * https://code.google.com/p/crypto-js/issues/detail?id=84
 * https://crypto-js.googlecode.com/svn-history/r667/branches/3.x/src/core.js
 * 
 * FIXED Int32Array & Uint32Array by Sergio Rando
 */

"use strict";

import { Encoder } from "./encoder.js"
import { Hex } from "./enc-hex.js"

/**
 * @typedef {(Array<number>|ArrayBuffer|Uint8Array|Int8Array|Uint8ClampedArray|Int16Array|Uint16Array|Int32Array|Uint32Array|Float32Array|Float64Array)} ArrayOfNumbers
 */ let ArrayOfNumbers;

/**
 * An array of 32-bit words.
 *
 * @property {Array<number>} words The array of 32-bit words.
 * @property {number} sigBytes The number of significant bytes in this word array.
 */
export class WordArray {
	/**
	 * @param {ArrayOfNumbers=} typedArray (Optional) An array of 32-bit words.
	 * @param {number=} sigBytes (Optional) The number of significant bytes in the words.
	 *
	 * @example
	 *
	 *     let wordArray = new WordArray();
	 *     let wordArray = new WordArray([0x00010203, 0x04050607]);
	 *     let wordArray = new WordArray([0x00010203, 0x04050607], 6);
	 */
	constructor(typedArray, sigBytes) {
		if (typeof ArrayBuffer !== 'undefined') {
			// Convert buffers to uint8
			if (typedArray instanceof ArrayBuffer) {
				typedArray = new Uint8Array(typedArray);
			}
			
			// Convert other array views to uint8
			if (
				typedArray instanceof Int8Array ||
				typedArray instanceof Uint8ClampedArray ||
				typedArray instanceof Int16Array ||
				typedArray instanceof Uint16Array ||
				typedArray instanceof Float32Array ||
				typedArray instanceof Float64Array
			) {
				typedArray = new Uint8Array(typedArray.buffer, typedArray.byteOffset, typedArray.byteLength);

				// Handle Uint8Array
				if (typedArray instanceof Uint8Array) {
					// Shortcut
					let typedArrayByteLength = typedArray.byteLength;

					// Extract bytes
					/** @type {Array<number>} */ let words = [];
					for (let i = 0; i < typedArrayByteLength; i++) {
						words[i >>> 2] |= (typedArray[i] << (24 - (i % 4) * 8));
					}

					// Initialize this word array
					this.words = words;
					this.sigBytes = typedArrayByteLength;

					return;
				}
			} else if (
				typedArray instanceof Int32Array ||
				typedArray instanceof Uint32Array
			) {
				// Shortcut
				let typedArrayLength = typedArray.length;

				// Extract bytes
				/** @type {Array<number>} */ let words = [];
				for (let i = 0; i < typedArrayLength; i++) {
					words[i] = typedArray[i] >>> 0;
				}

				// Initialize this word array
				this.words = words;
				this.sigBytes = typedArrayLength * 4;

				return;
			}
		}

		// Else call normal init
		let words = this.words = /** @type {Array<number>} */ ( typedArray || [] );

		if (sigBytes != undefined) {
			this.sigBytes = sigBytes;
		} else {
			this.sigBytes = words.length * 4;
		}
	}

	/**
	 * Converts this word array to a string.
	 *
	 * @param {Encoder=} encoder (Optional) The encoding strategy to use. Default: Hex
	 *
	 * @return {string} The stringified word array.
	 *
	 * @example
	 *
	 *     let string = wordArray + '';
	 *     let string = wordArray.toString();
	 *     let string = wordArray.toString(Utf8);
	 */
	toString(encoder) {
		return (encoder || Hex).stringify(this);
	}

	/**
	 * Concatenates a word array to this word array.
	 *
	 * @param {WordArray} wordArray The word array to append.
	 *
	 * @return {WordArray} This word array.
	 *
	 * @example
	 *
	 *     wordArray1.concat(wordArray2);
	 */
	concat(wordArray) {
		// Shortcuts
		let thisWords = this.words;
		let thatWords = wordArray.words;
		let thisSigBytes = this.sigBytes;
		let thatSigBytes = wordArray.sigBytes;

		// Clamp excess bits
		this.clamp();

		// Concat
		if (thisSigBytes % 4) {
			// Copy one byte at a time
			for (let i = 0; i < thatSigBytes; i++) {
				let thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
				thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
			}
		} else {
			// Copy one word at a time
			for (let i = 0; i < thatSigBytes; i += 4) {
				thisWords[(thisSigBytes + i) >>> 2] = thatWords[i >>> 2];
			}
		}
		this.sigBytes += thatSigBytes;

		// Chainable
		return this;
	}

	/**
	 * Removes insignificant bits.
	 *
	 * @example
	 *
	 *     wordArray.clamp();
	 */
	clamp() {
		// Shortcuts
		let words = this.words;
		let sigBytes = this.sigBytes;

		// Clamp
		words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
		words.length = Math.ceil(sigBytes / 4);
	}

	/**
	 * Creates a word array filled with random bytes.
	 *
	 * @param {number} nBytes The number of random bytes to generate.
	 *
	 * @return {WordArray} The random word array.
	 *
	 * @example
	 *
	 *     let wordArray = WordArray.random(16);
	 */
	static random(nBytes) {
		let words = [];
		for (let i = 0; i < nBytes; i += 4) {
			words.push((Math.random() * 0x100000000) | 0);
		}

		return new WordArray(words, nBytes);
	}
}
