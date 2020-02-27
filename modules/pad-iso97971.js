/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Padding } from "./padding.js"
import { ZeroPadding } from "./pad-zeropadding.js"

/**
 * ISO/IEC 9797-1 Padding Method 2.
 */
export class PaddingIso97971 extends Padding {
	/**
	 * @param {WordArray} data The data to pad.
	 * @param {number} blockSize The multiple that the data should be padded to.
	 */
	pad(data, blockSize) {
        // Add 0x80 byte
        data.concat(new WordArray([0x80000000], 1));

        // Zero pad the rest
        ZeroPadding.pad(data, blockSize);
	}

	/**
	 * @param {WordArray} data The data to unpad.
	 */
	unpad(data) {
        // Remove zero padding
        ZeroPadding.unpad(data);

        // Remove one more byte -- the 0x80 byte
        data.sigBytes--;
	}
}

export const Iso97971 = new PaddingIso97971();
