/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Padding } from "./padding.js"

/**
 * PKCS #5/7 padding strategy.
 */
export class PaddingPkcs7 extends Padding {
	/**
	 * Pads data using the algorithm defined in PKCS #5/7.
	 *
	 * @param {WordArray} data The data to pad.
	 * @param {number} blockSize The multiple that the data should be padded to.
	 *
	 * @example
	 *
	 *     CryptoJS.Pkcs7.pad(wordArray, 4);
	 */
	pad(data, blockSize) {
		// Shortcut
		let blockSizeBytes = blockSize * 4;

		// Count padding bytes
		let nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

		// Create padding word
		let paddingWord = (nPaddingBytes << 24) | (nPaddingBytes << 16) | (nPaddingBytes << 8) | nPaddingBytes;

		// Create padding
		let paddingWords = [];
		for (let i = 0; i < nPaddingBytes; i += 4) {
			paddingWords.push(paddingWord);
		}
		let padding = new WordArray(paddingWords, nPaddingBytes);

		// Add padding
		data.concat(padding);
	}

	/**
	 * Unpads data that had been padded using the algorithm defined in PKCS #5/7.
	 *
	 * @param {WordArray} data The data to unpad.
	 *
	 * @example
	 *
	 *     CryptoJS.Pkcs7.unpad(wordArray);
	 */
	unpad(data) {
		// Get number of padding bytes from last byte
		let nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

		// Remove padding
		data.sigBytes -= nPaddingBytes;
	}
}

export const Pkcs7 = new PaddingPkcs7();
