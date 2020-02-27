/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { Utf8 } from "./enc-utf8.js"

/**
 * @abstract buffered block algorithm template.
 *
 * The property blockSize must be implemented in a concrete subtype.
 *
 * @property {number} _minBufferSize The number of blocks that should be kept unprocessed in the buffer. Default: 0
 */
export class BufferedBlockAlgorithm {
	constructor() {
		this._minBufferSize = 0;

		/** @type {WordArray} */ this._data;
		/** @type {number} */ this._nDataBytes;
		/** @type {number} */ this.blockSize;
	}

	/**
	 * Resets this block algorithm's data buffer to its initial state.
	 *
	 * @example
	 *
	 *     bufferedBlockAlgorithm.reset();
	 */
	reset() {
		// Initial values
		this._data = new WordArray();
		this._nDataBytes = 0;
	}

	/**
	 * Adds new data to this block algorithm's buffer.
	 *
	 * @param {WordArray|string} data The data to append. Strings are converted to a WordArray using UTF-8.
	 *
	 * @example
	 *
	 *     bufferedBlockAlgorithm._append('data');
	 *     bufferedBlockAlgorithm._append(wordArray);
	 */
	_append(data) {
		// Convert string to WordArray, else assume WordArray already
		if (typeof data == 'string') {
			data = Utf8.parse(data);
		}

		// Append
		this._data.concat(data);
		this._nDataBytes += data.sigBytes;
	}

	/**
	 * Processes available data blocks.
	 *
	 * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
	 *
	 * @param {boolean=} doFlush Whether all blocks and partial blocks should be processed.
	 *
	 * @return {WordArray} The processed data.
	 *
	 * @example
	 *
	 *     let processedData = bufferedBlockAlgorithm._process();
	 *     let processedData = bufferedBlockAlgorithm._process(!!'flush');
	 */
	_process(doFlush) {
		// Shortcuts
		let data = this._data;
		let dataWords = data.words;
		let dataSigBytes = data.sigBytes;
		let blockSize = this.blockSize;
		let blockSizeBytes = blockSize * 4;

		// Count blocks ready
		let nBlocksReady = dataSigBytes / blockSizeBytes;
		if (doFlush) {
			// Round up to include partial blocks
			nBlocksReady = Math.ceil(nBlocksReady);
		} else {
			// Round down to include only full blocks,
			// less the number of blocks that must remain in the buffer
			nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
		}

		// Count words ready
		let nWordsReady = nBlocksReady * blockSize;

		// Count bytes ready
		let nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

		// Process blocks
		/** @type {Array<number>} */ let processedWords;
		if (nWordsReady) {
			for (let offset = 0; offset < nWordsReady; offset += blockSize) {
				// Perform concrete-algorithm logic
				this._doProcessBlock(dataWords, offset);
			}

			// Remove processed words
			processedWords = dataWords.splice(0, nWordsReady);
			data.sigBytes -= nBytesReady;
		}

		// Return processed words
		return new WordArray(processedWords, nBytesReady);
	}

	/**
	 * @abstract
	 * @param {Array<number>} dataWords 
	 * @param {number} offset 
	 */
	_doProcessBlock(dataWords, offset) {}
}

