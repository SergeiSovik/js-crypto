/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Encoder } from "./encoder.js"

/**
 * @param {number} word 
 * @returns {number}
 */
function swapEndian(word) {
	return ((word << 8) & 0xff00ff00) | ((word >>> 8) & 0x00ff00ff);
}

/**
 * UTF-16 BE encoding strategy.
 */
class EncoderUtf16BE extends Encoder {
	/**
	 * Converts a word array to a UTF-16 BE string.
	 *
	 * @param {WordArray} wordArray The word array.
	 *
	 * @return {string} The UTF-16 BE string.
	 *
	 * @static
	 *
	 * @example
	 *
	 *     let utf16String = Utf16.stringify(wordArray);
	 */
	stringify(wordArray) {
		// Shortcuts
		let words = wordArray.words;
		let sigBytes = wordArray.sigBytes;

		// Convert
		let utf16Chars = [];
		for (let i = 0; i < sigBytes; i += 2) {
			let codePoint = (words[i >>> 2] >>> (16 - (i % 4) * 8)) & 0xffff;
			utf16Chars.push(String.fromCharCode(codePoint));
		}

		return utf16Chars.join('');
	}

	/**
	 * Converts a UTF-16 BE string to a word array.
	 *
	 * @param {string} utf16Str The UTF-16 BE string.
	 *
	 * @return {WordArray} The word array.
	 *
	 * @static
	 *
	 * @example
	 *
	 *     let wordArray = Utf16.parse(utf16String);
	 */
	parse(utf16Str) {
		// Shortcut
		let utf16StrLength = utf16Str.length;

		// Convert
		let words = [];
		for (let i = 0; i < utf16StrLength; i++) {
			words[i >>> 1] |= utf16Str.charCodeAt(i) << (16 - (i % 2) * 16);
		}

		return new WordArray(words, utf16StrLength * 2);
	}
}

export const Utf16BE = new EncoderUtf16BE();

/**
 * UTF-16 LE encoding strategy.
 */
class EncoderUtf16LE extends Encoder {
	/**
	 * Converts a word array to a UTF-16 LE string.
	 *
	 * @param {WordArray} wordArray The word array.
	 *
	 * @return {string} The UTF-16 LE string.
	 *
	 * @static
	 *
	 * @example
	 *
	 *     let utf16Str = Utf16LE.stringify(wordArray);
	 */
	stringify(wordArray) {
		// Shortcuts
		let words = wordArray.words;
		let sigBytes = wordArray.sigBytes;

		// Convert
		let utf16Chars = [];
		for (let i = 0; i < sigBytes; i += 2) {
			let codePoint = swapEndian((words[i >>> 2] >>> (16 - (i % 4) * 8)) & 0xffff);
			utf16Chars.push(String.fromCharCode(codePoint));
		}

		return utf16Chars.join('');
	}

	/**
	 * Converts a UTF-16 LE string to a word array.
	 *
	 * @param {string} utf16Str The UTF-16 LE string.
	 *
	 * @return {WordArray} The word array.
	 *
	 * @static
	 *
	 * @example
	 *
	 *     let wordArray = Utf16LE.parse(utf16Str);
	 */
	parse(utf16Str) {
		// Shortcut
		let utf16StrLength = utf16Str.length;

		// Convert
		let words = [];
		for (let i = 0; i < utf16StrLength; i++) {
			words[i >>> 1] |= swapEndian(utf16Str.charCodeAt(i) << (16 - (i % 2) * 16));
		}

		return new WordArray(words, utf16StrLength * 2);
	}
}

export const Utf16LE = new EncoderUtf16LE();
