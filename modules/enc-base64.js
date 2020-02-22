/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Encoder } from "./encoder.js"

const _map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';

/**
 * Base64 encoding strategy.
 */
class EncoderBase64 extends Encoder {
	/**
	 * Converts a word array to a Base64 string.
	 *
	 * @param {WordArray} wordArray The word array.
	 *
	 * @return {string} The Base64 string.
	 *
	 * @example
	 *
	 *     let base64String = Base64.stringify(wordArray);
	 */
	stringify(wordArray) {
		// Shortcuts
		let words = wordArray.words;
		let sigBytes = wordArray.sigBytes;
		let map = _map;

		// Clamp excess bits
		wordArray.clamp();

		// Convert
		let base64Chars = [];
		for (let i = 0; i < sigBytes; i += 3) {
			let byte1 = (words[i >>> 2]       >>> (24 - (i % 4) * 8))       & 0xff;
			let byte2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
			let byte3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;

			let triplet = (byte1 << 16) | (byte2 << 8) | byte3;

			for (let j = 0; (j < 4) && (i + j * 0.75 < sigBytes); j++) {
				base64Chars.push(map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
			}
		}

		// Add padding
		let paddingChar = map.charAt(64);
		if (paddingChar) {
			while (base64Chars.length % 4) {
				base64Chars.push(paddingChar);
			}
		}

		return base64Chars.join('');
	}

	/**
	 * Converts a Base64 string to a word array.
	 *
	 * @param {string} base64Str The Base64 string.
	 *
	 * @return {WordArray} The word array.
	 *
	 * @static
	 *
	 * @example
	 *
	 *     let wordArray = Base64.parse(base64String);
	 */
	parse(base64Str) {
		// Shortcuts
		let base64StrLength = base64Str.length;
		let map = _map;

		// Ignore padding
		let paddingChar = map.charAt(64);
		if (paddingChar) {
			let paddingIndex = base64Str.indexOf(paddingChar);
			if (paddingIndex != -1) {
				base64StrLength = paddingIndex;
			}
		}

		// Convert
		let words = [];
		let nBytes = 0;
		for (let i = 0; i < base64StrLength; i++) {
			if (i % 4) {
				let bits1 = map.indexOf(base64Str.charAt(i - 1)) << ((i % 4) * 2);
				let bits2 = map.indexOf(base64Str.charAt(i)) >>> (6 - (i % 4) * 2);
				words[nBytes >>> 2] |= (bits1 | bits2) << (24 - (nBytes % 4) * 8);
				nBytes++;
			}
		}

		return new WordArray(words, nBytes);
	}
}

export const Base64 = new EncoderBase64();
