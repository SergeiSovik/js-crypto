/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Padding } from "./padding.js"

/**
 * Zero padding strategy.
 */
export class PaddingZeroPadding extends Padding {
	/**
	 * @param {WordArray} data The data to pad.
	 * @param {number} blockSize The multiple that the data should be padded to.
	 */
	pad(data, blockSize) {
        // Shortcut
        let blockSizeBytes = blockSize * 4;

        // Pad
        data.clamp();
        data.sigBytes += blockSizeBytes - ((data.sigBytes % blockSizeBytes) || blockSizeBytes);
	}

	/**
	 * @param {WordArray} data The data to unpad.
	 */
	unpad(data) {
        // Shortcut
        let dataWords = data.words;

        // Unpad
        let i = data.sigBytes - 1;
        while (!((dataWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff)) {
            i--;
        }
        data.sigBytes = i + 1;
	}
}

export const ZeroPadding = new PaddingZeroPadding();
