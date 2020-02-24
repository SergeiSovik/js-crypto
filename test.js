/*
 * Copyright 2020 Sergio Rando <segio.rando@yahoo.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

import { Hex } from "./modules/enc-hex.js"
import { Latin1 } from "./modules/enc-latin1"
import { Utf8 } from "./modules/enc-utf8.js"
import { Base64 } from "./modules/enc-base64"

import { RIPEMD160 } from "./modules/ripemd160.js"
import { MD5 } from "./modules/md5.js"
import { SHA1 } from "./modules/sha1.js"
import { SHA224 } from "./modules/sha224.js"
import { SHA256 } from "./modules/sha256.js"
import { SHA384 } from "./modules/sha384.js"
import { SHA512 } from "./modules/sha512.js"
import { SHA3 } from "./modules/sha3.js"
import { AES } from "./modules/aes.js"
import { OpenSSL } from "./modules/format.js";
import { DES, TripleDES } from "./modules/tripledes.js"
import { Rabbit } from "./modules/rabbit.js"
import { RabbitLegacy } from "./modules/rabbit-legacy.js"
import { RC4, RC4Drop } from "./modules/rc4.js"

let wa = Utf8.parse('ABCD');

let list = [
	[ 'Hex(ABCD)',		Hex.stringify(wa),				'41424344' ],
	[ 'Latin1(ABCD)',	Latin1.stringify(wa),			'ABCD' ],
	[ 'Utf8(ABCD)',		Utf8.stringify(wa),				'ABCD' ],
	[ 'Base64(ABCD)',	Base64.stringify(wa),			'QUJDRA=='],
	[ 'RIPEMD160(ABCD)',RIPEMD160('ABCD').toString(),	'494E236B8F3EE8DF57086FA0B7479F31CBFC06D7'.toLowerCase()],
	[ 'MD5(ABCD)',		MD5('ABCD').toString(),			'cb08ca4a7bb5f9683c19133a84872ca7'.toLowerCase() ],
	[ 'SHA1(ABCD)',		SHA1('ABCD').toString(),		'fb2f85c88567f3c8ce9b799c7c54642d0c7b41f6'.toLowerCase() ],
	[ 'SHA224(ABCD)',	SHA224('ABCD').toString(),		'44a1d724940a36e1b7adee6b5c7bafab2368bb02ddda3c90d74f60b6'.toLowerCase() ],
	[ 'SHA256(ABCD)',	SHA256('ABCD').toString(),		'e12e115acf4552b2568b55e93cbd39394c4ef81c82447fafc997882a02d23677'.toLowerCase() ],
	[ 'SHA384(ABCD)',	SHA384('ABCD').toString(),		'6f17e23899d2345a156baf69e7c02bbdda3be057367849c02add6a4aecbbd039a660ba815c95f2f145883600b7e9133d'.toLowerCase() ],
	[ 'SHA512(ABCD)',	SHA512('ABCD').toString(),		'49ec55bd83fcd67838e3d385ce831669e3f815a7f44b7aa5f8d52b5d42354c46d89c8b9d06e47a797ae4fbd22291be15bcc35b07735c4a6f92357f93d5a33d9b'.toLowerCase() ],
	[ 'SHA3(ABCD)',		SHA3('ABCD').toString(),		'5a0b238d044abb7bda3cb50998f35ccc837ae5abfe0baca4cca4a95d8d7dd045e0704734043a5557150140fdcca1662f9d6d7e2fe62a24bc4b9fbeab09d48462'.toLowerCase() ],
];

for (let i = 0; i < list.length; i++) {
	console.log(list[i][0], list[i][1] == list[i][2] ? 'OK => ' + list[i][1] : ('FAIL: ' + list[i][1] + ' != ' + list[i][2]));
}

{
	let data = 'ABCD';
	let password = '1234';
	let enc = AES.encrypt(data, password).toString(OpenSSL);
	let dec = AES.decrypt(enc, password, {'format': OpenSSL}).toString(Utf8);

	console.log('AES(' + data + ')', data == dec ? 'OK => ' + enc : ('FAIL: ' + data +  ' => ' + enc + ' != ' + dec));
}

{
	let data = 'ABCD';
	let password = '1234';
	let enc = DES.encrypt(data, password).toString(OpenSSL);
	let dec = DES.decrypt(enc, password, {'format': OpenSSL}).toString(Utf8);

	console.log('DES(' + data + ')', data == dec ? 'OK => ' + enc : ('FAIL: ' + data +  ' => ' + enc + ' != ' + dec));
}

{
	let data = 'ABCD';
	let password = '1234';
	let enc = TripleDES.encrypt(data, password).toString(OpenSSL);
	let dec = TripleDES.decrypt(enc, password, {'format': OpenSSL}).toString(Utf8);

	console.log('TripleDES(' + data + ')', data == dec ? 'OK => ' + enc : ('FAIL: ' + data +  ' => ' + enc + ' != ' + dec));
}

{
	let data = 'ABCD';
	let password = '1234';
	let enc = Rabbit.encrypt(data, password).toString(OpenSSL);
	let dec = Rabbit.decrypt(enc, password, {'format': OpenSSL}).toString(Utf8);

	console.log('Rabbit(' + data + ')', data == dec ? 'OK => ' + enc : ('FAIL: ' + data +  ' => ' + enc + ' != ' + dec));
}

{
	let data = 'ABCD';
	let password = '1234';
	let enc = RabbitLegacy.encrypt(data, password).toString(OpenSSL);
	let dec = RabbitLegacy.decrypt(enc, password, {'format': OpenSSL}).toString(Utf8);

	console.log('RabbitLegacy(' + data + ')', data == dec ? 'OK => ' + enc : ('FAIL: ' + data +  ' => ' + enc + ' != ' + dec));
}

{
	let data = 'ABCD';
	let password = '1234';
	let enc = RC4.encrypt(data, password).toString(OpenSSL);
	let dec = RC4.decrypt(enc, password, {'format': OpenSSL}).toString(Utf8);

	console.log('RC4(' + data + ')', data == dec ? 'OK => ' + enc : ('FAIL: ' + data +  ' => ' + enc + ' != ' + dec));
}

{
	let data = 'ABCD';
	let password = '1234';
	let enc = RC4Drop.encrypt(data, password).toString(OpenSSL);
	let dec = RC4Drop.decrypt(enc, password, {'format': OpenSSL}).toString(Utf8);

	console.log('RC4Drop(' + data + ')', data == dec ? 'OK => ' + enc : ('FAIL: ' + data +  ' => ' + enc + ' != ' + dec));
}
