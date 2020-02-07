/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"

/**
 * @abstract Encoder namespace.
 */
export class Encoder {
	/**
	 * @abstract Converts a word array to a hex string.
	 * @param {WordArray} wordArray The word array.
	 * @return {string} The hex string.
	 */
	stringify(wordArray) {}

	/**
	 * Converts a hex string to a word array.
	 * @param {string} hexStr The hex string.
	 * @return {WordArray} The word array.
	 */
	parse(hexStr) {}
}
