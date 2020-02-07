/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Padding } from "./padding.js"

/**
 * A noop padding strategy.
 */
export class PaddingNoPadding extends Padding {
	/**
	 * @param {WordArray} data The data to pad.
	 * @param {number} blockSize The multiple that the data should be padded to.
	 */
	pad(data, blockSize) {
	}

	/**
	 * @param {WordArray} data The data to unpad.
	 */
	unpad(data) {
	}
}

export const NoPadding = new PaddingNoPadding();
