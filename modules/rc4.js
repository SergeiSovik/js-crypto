"use strict";

/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function () {
    // Shortcuts
    let C = CryptoJS;
    let C_lib = C.lib;
    let StreamCipher = C_lib.StreamCipher;
    let C_algo = C.algo;

    /**
     * RC4 stream cipher algorithm.
     */
    let RC4 = C_algo.RC4 = StreamCipher.extend({
        _doReset() {
            // Shortcuts
            let key = this._key;
            let keyWords = key.words;
            let keySigBytes = key.sigBytes;

            // Init sbox
            let S = this._S = [];
            for (let i = 0; i < 256; i++) {
                S[i] = i;
            }

            // Key setup
            for (let i = 0, j = 0; i < 256; i++) {
                let keyByteIndex = i % keySigBytes;
                let keyByte = (keyWords[keyByteIndex >>> 2] >>> (24 - (keyByteIndex % 4) * 8)) & 0xff;

                j = (j + S[i] + keyByte) % 256;

                // Swap
                let t = S[i];
                S[i] = S[j];
                S[j] = t;
            }

            // Counters
            this._i = this._j = 0;
        },

        _doProcessBlock(M, offset) {
            M[offset] ^= generateKeystreamWord.call(this);
        },

        keySize: 256/32,

        ivSize: 0
    });

    function generateKeystreamWord() {
        // Shortcuts
        let S = this._S;
        let i = this._i;
        let j = this._j;

        // Generate keystream word
        let keystreamWord = 0;
        for (let n = 0; n < 4; n++) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;

            // Swap
            let t = S[i];
            S[i] = S[j];
            S[j] = t;

            keystreamWord |= S[(S[i] + S[j]) % 256] << (24 - n * 8);
        }

        // Update counters
        this._i = i;
        this._j = j;

        return keystreamWord;
    }

    /**
     * Shortcut functions to the cipher's object interface.
     *
     * @example
     *
     *     let ciphertext = CryptoJS.RC4.encrypt(message, key, cfg);
     *     let plaintext  = CryptoJS.RC4.decrypt(ciphertext, key, cfg);
     */
    C.RC4 = StreamCipher._createHelper(RC4);

    /**
     * Modified RC4 stream cipher algorithm.
     */
    let RC4Drop = C_algo.RC4Drop = RC4.extend({
        /**
         * Configuration options.
         *
         * @property {number} drop The number of keystream words to drop. Default 192
         */
        cfg: RC4.cfg.extend({
            drop: 192
        }),

        _doReset() {
            RC4._doReset.call(this);

            // Drop
            for (let i = this.cfg.drop; i > 0; i--) {
                generateKeystreamWord.call(this);
            }
        }
    });

    /**
     * Shortcut functions to the cipher's object interface.
     *
     * @example
     *
     *     let ciphertext = CryptoJS.RC4Drop.encrypt(message, key, cfg);
     *     let plaintext  = CryptoJS.RC4Drop.decrypt(ciphertext, key, cfg);
     */
    C.RC4Drop = StreamCipher._createHelper(RC4Drop);
}());
