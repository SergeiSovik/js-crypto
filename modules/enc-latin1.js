/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Encoder } from "./encoder.js"

/**
 * Latin1 encoding strategy.
 */
class EncoderLatin1 extends Encoder {
	/**
	 * Converts a word array to a Latin1 string.
	 *
	 * @param {WordArray} wordArray The word array.
	 *
	 * @return {string} The Latin1 string.
	 *
	 * @example
	 *
	 *     let latin1String = Latin1.stringify(wordArray);
	 */
	stringify(wordArray) {
		// Shortcuts
		let words = wordArray.words;
		let sigBytes = wordArray.sigBytes;

		// Convert
		let latin1Chars = [];
		for (let i = 0; i < sigBytes; i++) {
			let bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
			latin1Chars.push(String.fromCharCode(bite));
		}

		return latin1Chars.join('');
	}

	/**
	 * Converts a Latin1 string to a word array.
	 *
	 * @param {string} latin1Str The Latin1 string.
	 *
	 * @return {WordArray} The word array.
	 *
	 * @static
	 *
	 * @example
	 *
	 *     let wordArray = Latin1.parse(latin1String);
	 */
	parse(latin1Str) {
		// Shortcut
		let latin1StrLength = latin1Str.length;

		// Convert
		let words = [];
		for (let i = 0; i < latin1StrLength; i++) {
			words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
		}

		return new WordArray(words, latin1StrLength);
	}
}

export const Latin1 = new EncoderLatin1();
