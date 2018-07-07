'use strict';

const crypto = require('crypto');

class Cipher {
  constructor(key) {
    this.key = key;
  }

  encode(str){
    // generate IV(Initialization vector)
    const iv = crypto.pbkdf2Sync(this.key, crypto.randomBytes(16),10000, 16, 'sha512');
    // genrate binary key
    const key = Buffer.from(this.key, 'binary');
    // create encoder
    const cipher = crypto.createCipheriv("aes-256-ctr", key, iv);

    let encodedText = cipher.update(str, 'utf8', 'base64');

    encodedText += cipher.final();

    return encodedText + "." + iv.toString('base64');
  }

  decode(str){
    const encodedString = str.split(".")[0];

    const iv = Buffer.from(str.split(".")[1], 'base64');

    const key = Buffer.from(this.key, 'binary');

    const decipher = crypto.createDecipheriv("aes-256-ctr", key, iv);

    let decodedText = decipher.update(encodedString, 'base64');

    decodedText += decipher.final();

    return decodedText;
  }
}

module.exports = Cipher;
