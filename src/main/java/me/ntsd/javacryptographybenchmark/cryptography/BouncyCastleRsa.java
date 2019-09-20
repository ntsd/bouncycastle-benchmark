package me.ntsd.javacryptographybenchmark.cryptography;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;


public class BouncyCastleRsa {

    private AsymmetricBlockCipher encryptEngine;
    private AsymmetricBlockCipher decryptEngine;

    public BouncyCastleRsa() {
        Security.addProvider(new BouncyCastleProvider());

        AsymmetricCipherKeyPair keyPair = generateKeys();
        final AsymmetricKeyParameter publicKey = keyPair.getPublic();
        final AsymmetricKeyParameter privateKey = keyPair.getPrivate();

        encryptEngine = new RSAEngine();
        encryptEngine.init(true, publicKey); // true for cryptography

        decryptEngine = new RSAEngine();
        decryptEngine.init(false, privateKey); // false for decryption
    }

    private AsymmetricCipherKeyPair generateKeys() {
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(new RSAKeyGenerationParameters(
                BigInteger.valueOf(0x10001), // public exponent
                new SecureRandom(), // random number generator
                1024, // key size
                64 // certainty
        ));

        return generator.generateKeyPair();
    }

    public byte[] encrypt(byte[] data) throws InvalidCipherTextException {
        return encryptEngine.processBlock(data, 0, data.length);
    }

    public byte[] decrypt(byte[] encryptedBytes) throws InvalidCipherTextException {
        return decryptEngine.processBlock(encryptedBytes, 0, encryptedBytes.length);
    }
}
