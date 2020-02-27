/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { WordArray } from "./wordarray.js"
import { BufferedBlockAlgorithm } from "./algo.js"

/**
 * @abstract hasher template.
 *
 * @property {number} blockSize The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
 */
export class Hasher extends BufferedBlockAlgorithm {
	/**
	 * @example
	 *
	 *     let hasher = new SHA256();
	 */
	constructor() {
		super();

		this.blockSize = 512/32;

		/** @type {WordArray} */ this._hash;

		this.init();
	}

	/**
	 * Initializes a newly created hasher.
	 * 
	 * @returns {Hasher} this
	 */
	init() {
		// Set initial values
		this.reset();

		return this;
	}

	/**
	 * Resets this hasher to its initial state.
	 *
	 * @example
	 *
	 *     hasher.reset();
	 */
	reset() {
		// Reset data buffer
		super.reset();

		// Perform concrete-hasher logic
		this._doReset();
	}
	
	/**
	 * @abstract
	 */
	_doReset() {}

	/**
	 * Updates this hasher with a message.
	 *
	 * @param {WordArray|string} messageUpdate The message to append.
	 *
	 * @return {Hasher} This hasher.
	 *
	 * @example
	 *
	 *     hasher.update('message');
	 *     hasher.update(wordArray);
	 */
	update(messageUpdate) {
		// Append
		this._append(messageUpdate);

		// Update the hash
		this._process();

		// Chainable
		return this;
	}

	/**
	 * Finalizes the hash computation.
	 * Note that the finalize operation is effectively a destructive, read-once operation.
	 *
	 * @param {(WordArray|string)=} messageUpdate (Optional) A final message update.
	 *
	 * @return {WordArray} The hash.
	 *
	 * @example
	 *
	 *     let hash = hasher.finalize();
	 *     let hash = hasher.finalize('message');
	 *     let hash = hasher.finalize(wordArray);
	 */
	finalize(messageUpdate) {
		// Final message update
		if (messageUpdate !== undefined) {
			this._append(messageUpdate);
		}

		// Perform concrete-hasher logic
		let hash = this._doFinalize();

		return hash;
	}

	/**
	 * @abstract
	 * @returns {WordArray}
	 */
	_doFinalize() {}
}
