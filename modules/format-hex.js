/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { Formatter } from "./format.js"
import { CipherParams } from "./cipher-params.js"
import { Hex as EncoderHex } from "./enc-hex.js"
import { Dictionary } from "./../../../include/type.js"

/**
 * Hex formatting strategy.
 */
export class FormatterHex extends Formatter {
	/**
	 * Converts the ciphertext of a cipher params object to a hexadecimally encoded string.
	 *
	 * @param {CipherParams} cipherParams The cipher params object.
	 *
	 * @return {string} The hexadecimally encoded string.
	 *
	 * @example
	 *
	 *     let hexString = Hex.stringify(cipherParams);
	 */
	stringify(cipherParams) {
		return cipherParams.ciphertext.toString(EncoderHex);
	}

	/**
	 * Converts a hexadecimally encoded ciphertext string to a cipher params object.
	 *
	 * @param {string} input The hexadecimally encoded string.
	 *
	 * @return {CipherParams} The cipher params object.
	 *
	 * @example
	 *
	 *     let cipherParams = Hex.parse(hexString);
	 */
	parse(input) {
		let ciphertext = EncoderHex.parse(input);
		return new CipherParams(/** @type {Dictionary} */ ( { 'ciphertext': ciphertext } ));
	}
}

export const Hex = new FormatterHex();
