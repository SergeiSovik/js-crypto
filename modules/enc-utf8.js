/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Encoder } from "./encoder.js"
import { Latin1 } from "./enc-latin1.js"

/**
 * UTF-8 encoding strategy.
 */
class EncoderUtf8 extends Encoder {
	/**
	 * Converts a word array to a UTF-8 string.
	 *
	 * @param {WordArray} wordArray The word array.
	 *
	 * @return {string} The UTF-8 string.
	 *
	 * @example
	 *
	 *     let utf8String = Utf8.stringify(wordArray);
	 */
	stringify(wordArray) {
		try {
			return decodeURIComponent(escape(Latin1.stringify(wordArray)));
		} catch (e) {
			throw new Error('Malformed UTF-8 data');
		}
	}

	/**
	 * Converts a UTF-8 string to a word array.
	 *
	 * @param {string} utf8Str The UTF-8 string.
	 *
	 * @return {WordArray} The word array.
	 *
	 * @example
	 *
	 *     let wordArray = Utf8.parse(utf8String);
	 */
	parse(utf8Str) {
		return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
	}
}

export const Utf8 = new EncoderUtf8();
