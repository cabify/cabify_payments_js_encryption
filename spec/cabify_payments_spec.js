describe("CabifyPayments", function () {
  it("has a public encryption key", function () {
    var cabifyPayments = CabifyPayments.create("a public key");
    expect(cabifyPayments.publicKey).toMatch("a public key");
  });

  describe("encrypt", function () {
    var privateKey = "MIICXgIBAAKBgQsuU3jiFN8sWjjk/CvhpBUuKTVvDdAN7+3P+PAJxkeuq/c+/+F2KeW8aW4ABmtO6y+TYtvJCVtha/mx4rr9RnUa309sBekaXV3gjk5j91/z2/PNzmvuHnn2YAOUZhOM/2za+triLlm/h52quyoEL5B5wH3XgxAaWRxiHvLH66B1BwIDAQABAoGBCc4ACNtIrkP4gjfbIqfl+WTXYjIWjMIMCiD8DZKku6tixZgLTy0NpJZKZdnDx0oXV0sJv+5VNDsEMpxZVNxRcs3V8UTDJZu6QnKLkH3gGP9kfSMncfrz1jt1riBBd0PKGkgGU3FxjEIq7EawTv/xus7A+K2RLPZePAEN57N6tWvhAkEDb9B8NhAenON3FiN9IraCKAvRnHgbZOaJhFV+zaGIzv0bxx1GivQ9eHPmk0xPlx2k9hfPm0FcmqntgDxlcuNl/wJBA0DaMoeO79UMWwcicM08n39OHEzxD0DhZBeRcTVhJWMOntVBFDwkgBgPrrNEOFs2s8ZdhThXsTr5soCUL44NwPkCQQDYN9puxuNfFx+rFymnoEa4ZL8svu+simN9XC1/h5VBmT58Xpt5hrCcq48c4AInVye1OwDQXO3PLLerbixYYb4tAkAsh34MIWhRS8fSKdU+I++jLtn0gy79mQ9w8yXKZNdK5I05ebFLRehTYQNGMm+Q8OvLv1RQHuAq9w7EMSgZwEKBAkECZ3PhNh7S8KIPyrVjzdQZP+XXvpZj7yZbKosskk2cFUUc5zXOgIrMXCu2hyMWZF1qxKYHus5z1hbo3oNMYDeDrQ==";

    var publicKey = "MIGJAoGBCy5TeOIU3yxaOOT8K+GkFS4pNW8N0A3v7c/48AnGR66r9z7/4XYp5bxpbgAGa07rL5Ni28kJW2Fr+bHiuv1GdRrfT2wF6RpdXeCOTmP3X/Pb883Oa+4eefZgA5RmE4z/bNr62uIuWb+Hnaq7KgQvkHnAfdeDEBpZHGIe8sfroHUHAgMBAAE=";

    var decrypt = function (value) {
      var key = CabifyPayments.pidCryptUtil.decodeBase64(privateKey);
      var rsa = new CabifyPayments.pidCrypt.RSA();
      var asn = CabifyPayments.pidCrypt.ASN1.decode(CabifyPayments.pidCryptUtil.toByteArray(key));
      var tree = asn.toHexTree();
      rsa.setPrivateKeyFromASN(tree);

      var data = value.split(/\|/)
      var cryptedAesKey = data[1];
      var cryptedAesIv  = data[2];
      var cipherText    = data[3];

      var aesKey = rsa.decryptRaw(CabifyPayments.pidCryptUtil.convertToHex(CabifyPayments.pidCryptUtil.decodeBase64(cryptedAesKey)));
      var aesKeyBits = CabifyPayments.sjcl.codec.base64.toBits(aesKey);
      var aes = new CabifyPayments.sjcl.cipher.aes(aesKeyBits);

      var iv = rsa.decryptRaw(CabifyPayments.pidCryptUtil.convertToHex(CabifyPayments.pidCryptUtil.decodeBase64(cryptedAesIv)));
      var ivBits = CabifyPayments.sjcl.codec.base64.toBits(iv);

      var cipherTextBits = CabifyPayments.sjcl.codec.base64.toBits(cipherText);

      var plainTextBits = CabifyPayments.sjcl.mode.cbc.decrypt(aes, cipherTextBits, ivBits);
      var plainText = CabifyPayments.sjcl.codec.utf8String.fromBits(plainTextBits);

      return plainText;
    };

    it("encrypts the given text with the public key", function () {
      var cabifyPayments = CabifyPayments.create(publicKey);
      var encrypted = cabifyPayments.encrypt("test data");

      expect(decrypt(encrypted)).toEqual("test data");
    });

    it("encrypts the given lengthy text with the public key", function () {
      var cabifyPayments = CabifyPayments.create(publicKey);
      var plainText = "lengthy test data lenghty test data lengthy test data 123456";
      var encrypted = cabifyPayments.encrypt(plainText);

      expect(decrypt(encrypted)).toEqual(plainText);
    });

    it("prepends the encrypted data with $cp1", function () {
      var cabifyPayments = CabifyPayments.create(publicKey);
      var encrypted = cabifyPayments.encrypt("test data");

      expect(encrypted).toMatch(/^\$cp1\$/);
    });
  });
});
