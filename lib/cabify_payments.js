for (k in sjcl.beware) { if (sjcl.beware.hasOwnProperty(k)) { sjcl.beware[k](); } }

CabifyPayments = {
  pidCrypt: pidCrypt,
  pidCryptUtil: pidCryptUtil,
  sjcl: sjcl
};

CabifyPayments.create = function (publicKey) {
  var my = {
    publicKey: publicKey,
  };

  var generateAes = function () {
    return {
      key: sjcl.random.randomWords(8, 0),
      iv:  sjcl.random.randomWords(4, 0),
      encrypt: function(plainText) {
        var aes = new sjcl.cipher.aes(this.key);
        var plainTextBits = sjcl.codec.utf8String.toBits(plainText);
        var cipherTextBits = sjcl.mode.cbc.encrypt(aes, plainTextBits, this.iv);
        return sjcl.codec.base64.fromBits(cipherTextBits);
      },
      encryptWithRsa: function(rsa, value) {
        var encryptedKeyHex = rsa.encryptRaw(sjcl.codec.base64.fromBits(value));
        return pidCryptUtil.encodeBase64(pidCryptUtil.convertFromHex(encryptedKeyHex));
      },
    };
  };

  var loadRsaKey = function () {
    var key = pidCryptUtil.decodeBase64(my.publicKey);
    var rsa = new pidCrypt.RSA();
    var keyBytes = pidCryptUtil.toByteArray(key);
    var asn = pidCrypt.ASN1.decode(keyBytes);
    var tree = asn.toHexTree();
    rsa.setPublicKeyFromASN(tree);

    return rsa;
  };

  var encrypt = function (text) {
    var aes = generateAes();
    var aesEncryptedData = aes.encrypt(text);
    var rsa = loadRsaKey();

    return ["$cp1", aes.encryptWithRsa(rsa, aes.key), aes.encryptWithRsa(rsa, aes.iv), aesEncryptedData].join('|');
  };

  return {
    encrypt: encrypt,
    publicKey: my.publicKey,
    version: '1.0.0'
  };
};
