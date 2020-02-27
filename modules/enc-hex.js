/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Encoder } from "./encoder.js"

/**
 * Hex encoding strategy.
 */
class EncoderHex extends Encoder {
	/**
	 * Converts a word array to a hex string.
	 *
	 * @param {WordArray} wordArray The word array.
	 *
	 * @return {string} The hex string.
	 *
	 * @example
	 *
	 *     let hexString = Hex.stringify(wordArray);
	 */
	stringify(wordArray) {
		// Shortcuts
		let words = wordArray.words;
		let sigBytes = wordArray.sigBytes;

		// Convert
		let hexChars = [];
		for (let i = 0; i < sigBytes; i++) {
			let bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
			hexChars.push((bite >>> 4).toString(16));
			hexChars.push((bite & 0x0f).toString(16));
		}

		return hexChars.join('');
	}

	/**
	 * Converts a hex string to a word array.
	 *
	 * @param {string} hexStr The hex string.
	 *
	 * @return {WordArray} The word array.
	 *
	 * @static
	 *
	 * @example
	 *
	 *     let wordArray = Hex.parse(hexString);
	 */
	parse(hexStr) {
		// Shortcut
		let hexStrLength = hexStr.length;

		// Convert
		let words = [];
		for (let i = 0; i < hexStrLength; i += 2) {
			words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
		}

		return new WordArray(words, hexStrLength / 2);
	}
}

export const Hex = new EncoderHex();
