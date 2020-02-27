/**
 * Original work Copyright (c) 2009-2013 Jeff Mott
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 */

"use strict";

import { Mode, ModeCreator, ModeProcessor } from "./mode.js"
import { Padding } from "./padding.js"
import { Formatter, OpenSSL } from "./format.js"
import { CipherParams } from "./cipher-params.js"
import { WordArray } from "./wordarray.js"
import { ClassEvpKDF } from "./evpkdf.js"
import { CBC } from "./mode-cbc.js"
import { Pkcs7 } from "./pad-pkcs7.js"
import { CipherProcessor, ConfigCipher } from "./cipher-processor.js"
import { Dictionary } from "./../../../include/type.js"

/** @const {number} ENC_XFORM_MODE A constant representing encryption mode. */
export const ENC_XFORM_MODE = 1;

/** @const {number} DEC_XFORM_MODE A constant representing decryption mode. */
export const DEC_XFORM_MODE = 2;

/**
 * @abstract base cipher template.
 */
export class Cipher {
	constructor() {
		this.keySize = 128/32;
		this.ivSize = 128/32;
	}

	/**
	 * @abstract Creates this cipher in encryption mode.
	 *
	 * @param {WordArray} key The key.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 *
	 * @return {CipherProcessor} A cipher instance.
	 *
	 * @example
	 *
	 *     var cipher = AES.createEncryptor(keyWordArray, { 'iv': ivWordArray });
	 */
	createEncryptor(key, cfg) {
		// return new BlockCipherProcessor(ENC_XFORM_MODE, key, cfg);
	}

	/**
	 * Creates this cipher in decryption mode.
	 *
	 * @param {WordArray} key The key.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 *
	 * @return {CipherProcessor} A cipher instance.
	 *
	 * @example
	 *
	 *     var cipher = AES.createDecryptor(keyWordArray, { 'iv': ivWordArray });
	 */
	createDecryptor(key, cfg) {
		// return new BlockCipherProcessor(DEC_XFORM_MODE, key, cfg);
	}
}

/**
 * Creates shortcut functions to a cipher's object interface.
 *
 * @example
 *
 *     let AES = new CipherHelper(CipherAES)
 */
export class CipherHelper {
	/**
	 * @param {Cipher} cipher The cipher to create a helper for.
	 */
	constructor(cipher) {
		this.cipher = cipher;
	}

	/**
	 * @param {WordArray|string} message The message to encrypt.
	 * @param {WordArray|string} key The password.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 * @returns {CipherParams}
	 */
	encrypt(message, key, cfg) {
		if (typeof key == 'string') {
			return PasswordBasedCipher.encrypt(this.cipher, message, key, cfg);
		}
		
		return SerializableCipher.encrypt(this.cipher, message, key, cfg);
	}

	/**
	 * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
	 * @param {WordArray|string} key The key.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 * @returns {WordArray}
	 */
	decrypt(ciphertext, key, cfg) {
		if (typeof key == 'string') {
			return PasswordBasedCipher.decrypt(this.cipher, ciphertext, key, cfg);
		}

		return SerializableCipher.decrypt(this.cipher, ciphertext, key, cfg);
	}
}

/**
 * @abstract base stream cipher template.
 *
 * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 1 (32 bits)
 */
export class StreamCipherProcessor extends CipherProcessor {
	/**
	 * @param {number} xformMode Either the encryption or decryption transormation mode constant.
	 * @param {WordArray} key The key.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 */
	constructor(xformMode, key, cfg) {
		super(xformMode, key, cfg);

		this.blockSize = 1;
	}

	_doFinalize() {
		// Process partial blocks
		let finalProcessedBlocks = this._process(!!'flush');

		return finalProcessedBlocks;
	}
}

/**
 * Configuration options.
 *
 * @property {BlockCipherMode} mode The block mode to use. Default: CBC
 * @property {Padding} padding The padding strategy to use. Default: Pkcs7
 */
export class ConfigBlockCipherProcessor extends ConfigCipher {
	/**
	 * @param {Dictionary=} cfg
	 */
	constructor(cfg) {
		super(cfg);

		/** @type {Mode} */ this.mode = CBC;
		/** @type {Padding} */ this.padding = Pkcs7;

		let mode = cfg && cfg['mode'] || undefined; if (mode !== undefined && mode instanceof Mode) this.mode = mode;
		let padding = cfg && cfg['padding'] || undefined; if (padding !== undefined && padding instanceof Padding) this.padding = padding;
	}
}

/**
 * @abstract base block cipher template.
 *
 * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 4 (128 bits)
 */
export class BlockCipherProcessor extends CipherProcessor {
	/**
	 * @param {number} xformMode Either the encryption or decryption transormation mode constant.
	 * @param {WordArray} key The key.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 */
	constructor(xformMode, key, cfg) {
		super(xformMode, key, cfg);

		/** @type {ConfigBlockCipherProcessor} */ this.cfg;
		/** @type {ModeProcessor} */ this._mode;

		this.blockSize = 128/32;
	}

	/**
	 * @override
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 */
	updateConfig(cfg) {
		// Apply config defaults
		this.cfg = new ConfigBlockCipherProcessor(cfg);
	}

	reset() {
		// Reset cipher
		super.reset();

		// Shortcuts
		let cfg = this.cfg;
		let iv = cfg.iv;
		let mode = cfg.mode;

		// Reset block mode
		/** @type {ModeCreator} */ let modeCreator;
		if (this._xformMode == ENC_XFORM_MODE) {
			modeCreator = mode.createEncryptor.bind(mode);
		} else /* if (this._xformMode == DEC_XFORM_MODE) */ {
			modeCreator = mode.createDecryptor.bind(mode);

			// Keep at least one block in the buffer for unpadding
			this._minBufferSize = 1;
		}
		this._mode = modeCreator(this, iv && iv.words);
	}

	_doProcessBlock(words, offset) {
		this._mode.processBlock(words, offset);
	}

	_doFinalize() {
		// Shortcut
		let padding = this.cfg.padding;

		// Finalize
		/** @type {WordArray} */ let finalProcessedBlocks;
		if (this._xformMode == ENC_XFORM_MODE) {
			// Pad data
			padding.pad(this._data, this.blockSize);

			// Process final blocks
			finalProcessedBlocks = this._process(!!'flush');
		} else /* if (this._xformMode == DEC_XFORM_MODE) */ {
			// Process final blocks
			finalProcessedBlocks = this._process(!!'flush');

			// Unpad data
			padding.unpad(finalProcessedBlocks);
		}

		return finalProcessedBlocks;
	}

	/**
	 * @abstract
	 * @param {Array<number>} M 
	 * @param {number} offset 
	 */
	encryptBlock(M, offset) {}

	/**
	 * @abstract
	 * @param {Array<number>} M 
	 * @param {number} offset 
	 */
	decryptBlock(M, offset) {}
}

/**
 * Configuration options.
 *
 * @property {Formatter} format The formatting strategy to convert cipher param objects to and from a string. Default: OpenSSL
 */
export class CipherWrapperConfig {
	/**
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this hash computation.
	 */
	constructor(cfg) {
		/** @type {Formatter} */ this.format = OpenSSL;

		let format = cfg && cfg['format'] || undefined; if (format !== undefined && format instanceof Formatter) this.format = format;
	}
}

/**
 * A cipher wrapper that returns ciphertext as a serializable cipher params object.
 */
class CipherWrapper {
	/**
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this hash computation.
	 */
	constructor(cfg) {
		/** @type {CipherWrapperConfig} */ this.cfg;

		this.init(cfg);
	}

	/**
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this hash computation.
	 */
	init(cfg) {
		this.updateConfig(cfg);
	}

	/**
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this hash computation.
	 */
	updateConfig(cfg) {
		// Apply config defaults
		this.cfg = new CipherWrapperConfig(cfg);
	}

	/**
	 * @protected Encrypts a message.
	 *
	 * @param {Cipher} cipher The cipher algorithm to use.
	 * @param {WordArray|string} message The message to encrypt.
	 * @param {WordArray} key The key.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 *
	 * @return {CipherParams} A cipher params object.
	 */
	encryptSerialized(cipher, message, key, cfg) {
		// Encrypt
		let processor = cipher.createEncryptor(key, cfg);
		// Create and return serializable cipher params
		if (processor instanceof BlockCipherProcessor) {
			let blockProcessor = /** @type {BlockCipherProcessor} */ ( processor );
			let ciphertext = blockProcessor.finalize(message);

			// Shortcut
			let cipherCfg = blockProcessor.cfg;
	
			return new CipherParams(/** @type {Dictionary} */ ( {
				'ciphertext': ciphertext,
				'key': key,
				'iv': cipherCfg.iv,
				'algorithm': cipher,
				'mode': cipherCfg.mode,
				'padding': cipherCfg.padding,
				'blockSize': processor.blockSize,
				'formatter': cfg['format']
			} ));
		} else {
			let ciphertext = processor.finalize(message);

			// Shortcut
			let cipherCfg = processor.cfg;
	
			return new CipherParams(/** @type {Dictionary} */ ( {
				'ciphertext': ciphertext,
				'key': key,
				'iv': cipherCfg.iv,
				'algorithm': cipher,
				'blockSize': processor.blockSize,
				'formatter': cfg['format']
			} ));
		}
	}

	/**
	 * @protected Decrypts serialized ciphertext.
	 *
	 * @param {Cipher} cipher The cipher algorithm to use.
	 * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
	 * @param {WordArray} key The key.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 *
	 * @return {WordArray | null} The plaintext.
	 */
	decryptSerialized(cipher, ciphertext, key, cfg) {
		// Convert string to CipherParams
		if (!(cfg['format'] instanceof Formatter))
			return null;

		ciphertext = this._parse(ciphertext, /** @type {Formatter} */ ( cfg['format'] ));

		// Decrypt
		let processor = cipher.createDecryptor(key, cfg);
		let plaintext = processor.finalize(ciphertext.ciphertext);

		return plaintext;
	}

	/**
	 * Converts serialized ciphertext to CipherParams,
	 * else assumed CipherParams already and returns ciphertext unchanged.
	 *
	 * @param {CipherParams|string} ciphertext The ciphertext.
	 * @param {Formatter} format The formatting strategy to use to parse serialized ciphertext.
	 *
	 * @return {CipherParams} The unserialized ciphertext.
	 *
	 * @example
	 *
	 *     let ciphertextParams = SerializableCipher._parse(ciphertextStringOrParams, format);
	 */
	_parse(ciphertext, format) {
		if (typeof ciphertext == 'string') {
			return format.parse(ciphertext, this);
		} else {
			return ciphertext;
		}
	}
}

/**
 * A cipher wrapper that returns ciphertext as a serializable cipher params object.
 */
class ClassSerializableCipher extends CipherWrapper {
	/**
	 * Encrypts a message.
	 *
	 * @param {Cipher} cipher The cipher algorithm to use.
	 * @param {WordArray|string} message The message to encrypt.
	 * @param {WordArray} key The key.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 *
	 * @return {CipherParams} A cipher params object.
	 *
	 * @example
	 *
	 *     let ciphertextParams = SerializableCipher.encrypt(AES, message, key);
	 *     let ciphertextParams = SerializableCipher.encrypt(AES, message, key, { 'iv': iv });
	 *     let ciphertextParams = SerializableCipher.encrypt(AES, message, key, { 'iv': iv, 'format': OpenSSL });
	 */
	encrypt(cipher, message, key, cfg) {
		this.updateConfig(cfg);

		return this.encryptSerialized(cipher, message, key, cfg);
	}

	/**
	 * Decrypts serialized ciphertext.
	 *
	 * @param {Cipher} cipher The cipher algorithm to use.
	 * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
	 * @param {WordArray} key The key.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 *
	 * @return {WordArray} The plaintext.
	 *
	 * @static
	 *
	 * @example
	 *
	 *     let plaintext = SerializableCipher.decrypt(AES, formattedCiphertext, key, { 'iv': iv, 'format': OpenSSL });
	 *     let plaintext = SerializableCipher.decrypt(AES, ciphertextParams, key, { 'iv': iv, 'format': OpenSSL });
	 */
	decrypt(cipher, ciphertext, key, cfg) {
		this.updateConfig(cfg);

		return this.decryptSerialized(cipher, ciphertext, key, cfg);
	}
}

export const SerializableCipher = new ClassSerializableCipher();

/**
 * @abstract Key derivation function namespace.
 */
export class KDF {
	/**
	 * @abstract Derives a key and IV from a password.
	 *
	 * @param {string} password The password to derive from.
	 * @param {number} keySize The size in words of the key to generate.
	 * @param {number} ivSize The size in words of the IV to generate.
	 * @param {(WordArray|string)=} salt (Optional) A 64-bit salt to use. If omitted, a salt will be generated randomly.
	 *
	 * @return {CipherParams} A cipher params object with the key, IV, and salt.
	 */
	execute(password, keySize, ivSize, salt) {}
}

/**
 * OpenSSL key derivation function.
 */
export class ClassOpenSSLKdf extends KDF {
	/**
	 * Derives a key and IV from a password.
	 *
	 * @param {string} password The password to derive from.
	 * @param {number} keySize The size in words of the key to generate.
	 * @param {number} ivSize The size in words of the IV to generate.
	 * @param {(WordArray|string)=} salt (Optional) A 64-bit salt to use. If omitted, a salt will be generated randomly.
	 *
	 * @return {CipherParams} A cipher params object with the key, IV, and salt.
	 *
	 * @example
	 *
	 *     let derivedParams = OpenSSLKdf.execute('Password', 256/32, 128/32);
	 *     let derivedParams = OpenSSLKdf.execute('Password', 256/32, 128/32, 'saltsalt');
	 */
	execute(password, keySize, ivSize, salt) {
		// Generate random salt
		if (!salt) {
			salt = WordArray.random(64/8);
		}

		// Derive key and IV
		let key = new ClassEvpKDF({ 'keySize': keySize + ivSize }).compute(password, salt);

		// Separate key and IV
		let iv = new WordArray(key.words.slice(keySize), ivSize * 4);
		key.sigBytes = keySize * 4;

		// Return params
		return new CipherParams(/** @type {Dictionary} */ ( { 'key': key, 'iv': iv, 'salt': salt } ));
	}
}

export const OpenSSLKdf = new ClassOpenSSLKdf();

/**
 * Configuration options.
 *
 * @property {KDF} kdf The key derivation function to use to generate a key and IV from a password. Default: OpenSSL
 */
export class PasswordBasedCipherConfig extends CipherWrapperConfig {
	/**
	 * @param {Dictionary=} cfg
	 */
	constructor(cfg) {
		super(cfg);

		this.kdf = OpenSSLKdf;

		let kdf = cfg && cfg['kdf'] || undefined; if (kdf !== undefined && kdf instanceof KDF) this.kdf = kdf;
	}
}

/**
 * A serializable cipher wrapper that derives the key from a password,
 * and returns ciphertext as a serializable cipher params object.
 */
export class ClassPasswordBasedCipher extends CipherWrapper {
	/**
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this hash computation.
	 */
	constructor(cfg) {
		super();

		/** @type {PasswordBasedCipherConfig} */ this.cfg;

		this.init(cfg);
	}

	/**
	 * @override
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this hash computation.
	 */
	updateConfig(cfg) {
		// Apply config defaults
		this.cfg = new PasswordBasedCipherConfig(cfg);
	}

	/**
	 * 
	 * Encrypts a message using a password.
	 *
	 * @param {Cipher} cipher The cipher algorithm to use.
	 * @param {WordArray|string} message The message to encrypt.
	 * @param {string} password The password.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 *
	 * @return {CipherParams} A cipher params object.
	 *
	 * @static
	 *
	 * @example
	 *
	 *     let ciphertextParams = ClassPasswordBasedCipher.encrypt(CipherAES, message, 'password');
	 *     let ciphertextParams = ClassPasswordBasedCipher.encrypt(CipherAES, message, 'password', { format: OpenSSL });
	 */
	encrypt(cipher, message, password, cfg) {
		this.updateConfig(cfg);

		// Derive key and other params
		let derivedParams = this.cfg.kdf.execute(password, cipher.keySize, cipher.ivSize);

		cfg = cfg || /** @type {Dictionary} */ ( {} );

		// Add IV to config
		cfg['iv'] = derivedParams.iv;

		// Encrypt
		let ciphertext = this.encryptSerialized(cipher, message, derivedParams.key, cfg);

		// Mix in derived params
		ciphertext.mixIn(derivedParams);

		return ciphertext;
	}

	/**
	 * Decrypts serialized ciphertext using a password.
	 *
	 * @param {Cipher} cipher The cipher algorithm to use.
	 * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
	 * @param {string} password The password.
	 * @param {Dictionary=} cfg (Optional) The configuration options to use for this operation.
	 *
	 * @return {WordArray} The plaintext.
	 *
	 * @static
	 *
	 * @example
	 *
	 *     let plaintext = ClassPasswordBasedCipher.decrypt(CipherAES, formattedCiphertext, 'password', { format: OpenSSL });
	 *     let plaintext = ClassPasswordBasedCipher.decrypt(CipherAES, ciphertextParams, 'password', { format: OpenSSL });
	 */
	decrypt(cipher, ciphertext, password, cfg) {
		this.updateConfig(cfg);

		// Convert string to CipherParams
		ciphertext = this._parse(ciphertext, this.cfg.format);

		// Derive key and other params
		let derivedParams = this.cfg.kdf.execute(password, cipher.keySize, cipher.ivSize, ciphertext.salt);

		cfg = cfg || /** @type {Dictionary} */ ( {} );

		// Add IV to config
		cfg['iv'] = derivedParams.iv;

		// Decrypt
		let plaintext = this.decryptSerialized(cipher, ciphertext, derivedParams.key, cfg);

		return plaintext;
	}
}

export const PasswordBasedCipher = new ClassPasswordBasedCipher();
