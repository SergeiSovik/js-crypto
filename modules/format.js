/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { CipherParams } from "./cipher-params.js"
import { WordArray } from "./wordarray.js"
import { Base64 } from "./enc-base64.js"
import { Dictionary } from "./../../../include/type.js"

/**
 * @abstract formatting strategy.
 */
export class Formatter {
	/**
	 * @abstract
	 * 
	 * @param {CipherParams} cipherParams The cipher params object.
	 *
	 * @return {string}
	 */
	stringify(cipherParams) {}

	/**
	 * @abstract
	 *
	 * @param {string} str
	 *
	 * @return {CipherParams} The cipher params object.
	 */
	parse(str, opt) {}
}

/**
 * OpenSSL formatting strategy.
 */
export class FormatterOpenSSL extends Formatter {
	/**
	 * Converts a cipher params object to an OpenSSL-compatible string.
	 *
	 * @param {CipherParams} cipherParams The cipher params object.
	 *
	 * @return {string} The OpenSSL-compatible string.
	 *
	 * @example
	 *
	 *     let openSSLString = OpenSSL.stringify(cipherParams);
	 */
	stringify(cipherParams) {
		// Shortcuts
		let ciphertext = cipherParams.ciphertext;
		let salt = cipherParams.salt;

		// Format
		/** @type {WordArray} */ let wordArray;
		if (salt) {
			wordArray = new WordArray([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext);
		} else {
			wordArray = ciphertext;
		}

		return wordArray.toString(Base64);
	}

	/**
	 * Converts an OpenSSL-compatible string to a cipher params object.
	 *
	 * @param {string} openSSLStr The OpenSSL-compatible string.
	 *
	 * @return {CipherParams} The cipher params object.
	 *
	 * @example
	 *
	 *     let cipherParams = format.OpenSSL.parse(openSSLString);
	 */
	parse(openSSLStr) {
		// Parse base64
		let ciphertext = Base64.parse(openSSLStr);

		// Shortcut
		let ciphertextWords = ciphertext.words;

		// Test for salt
		/** @type {WordArray} */ let salt;
		if (ciphertextWords[0] == 0x53616c74 && ciphertextWords[1] == 0x65645f5f) {
			// Extract salt
			salt = new WordArray(ciphertextWords.slice(2, 4));

			// Remove salt from ciphertext
			ciphertextWords.splice(0, 4);
			ciphertext.sigBytes -= 16;
		}

		return new CipherParams(/** @type {Dictionary} */ ( { 'ciphertext': ciphertext, 'salt': salt } ));
	}
}

export const OpenSSL = new FormatterOpenSSL();
