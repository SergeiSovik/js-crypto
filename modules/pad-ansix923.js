/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Padding } from "./padding.js"

/**
 * ANSI X.923 padding strategy.
 */
export class PaddingAnsiX923 extends Padding {
	/**
	 * @param {WordArray} data The data to pad.
	 * @param {number} blockSize The multiple that the data should be padded to.
	 */
	pad(data, blockSize) {
        // Shortcuts
        let dataSigBytes = data.sigBytes;
        let blockSizeBytes = blockSize * 4;

        // Count padding bytes
        let nPaddingBytes = blockSizeBytes - dataSigBytes % blockSizeBytes;

        // Compute last byte position
        let lastBytePos = dataSigBytes + nPaddingBytes - 1;

        // Pad
        data.clamp();
        data.words[lastBytePos >>> 2] |= nPaddingBytes << (24 - (lastBytePos % 4) * 8);
        data.sigBytes += nPaddingBytes;
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

export const AnsiX923 = new PaddingAnsiX923();
