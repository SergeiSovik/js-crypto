/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"

/**
 * @abstract Padding namespace.
 */
export class Padding {
	/**
	 * @abstract
	 * @param {WordArray} data The data to pad.
	 * @param {number} blockSize The multiple that the data should be padded to.
	 */
	pad(data, blockSize) {}

	/**
	 * @abstract
	 * @param {WordArray} data The data to unpad.
	 */
	unpad(data) {}
}
