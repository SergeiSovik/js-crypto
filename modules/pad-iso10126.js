/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Padding } from "./padding.js"

/**
 * ISO 10126 padding strategy.
 */
export class PaddingIso10126 extends Padding {
	/**
	 * @param {WordArray} data The data to pad.
	 * @param {number} blockSize The multiple that the data should be padded to.
	 */
	pad(data, blockSize) {
        // Shortcut
        let blockSizeBytes = blockSize * 4;

        // Count padding bytes
        let nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

        // Pad
        data.concat(WordArray.random(nPaddingBytes - 1)).
             concat(new WordArray([nPaddingBytes << 24], 1));
	}

	/**
	 * @param {WordArray} data The data to unpad.
	 */
	unpad(data) {
        // Get number of padding bytes from last byte
        let nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

        // Remove padding
        data.sigBytes -= nPaddingBytes;
	}
}

export const Iso10126 = new PaddingIso10126();
