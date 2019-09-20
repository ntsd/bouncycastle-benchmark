package me.ntsd.javacryptographybenchmark.encryption;

import me.ntsd.javacryptographybenchmark.benchmark.BenchmarkAlgorithm;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;


public class BouncyCastleRsaAndAesBenchmark implements BenchmarkAlgorithm {

    private KeyGenerator ivKeyGenerator;
    private byte[] secretKey;

    private Cipher encryptCipherAes;
    private Cipher decryptCipherAes;

    private AsymmetricBlockCipher encryptEngine;
    private AsymmetricBlockCipher decryptEngine;

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

    public BouncyCastleRsaAndAesBenchmark() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        Security.addProvider(new BouncyCastleProvider());

        // AES Init
        KeyGenerator aesKeyGenerator = KeyGenerator.getInstance("AES", "BC");
        aesKeyGenerator.init(128);  // AES 128 bit
        secretKey = aesKeyGenerator.generateKey().getEncoded();

        ivKeyGenerator = KeyGenerator.getInstance("AES", "BC");
        ivKeyGenerator.init(128); // iv is 128 bits

        encryptCipherAes = Cipher.getInstance("AES", "BC");
        decryptCipherAes = Cipher.getInstance("AES", "BC");

        // RSA Init
        AsymmetricCipherKeyPair keyPair = generateKeys();
        final AsymmetricKeyParameter privateKey = keyPair.getPrivate();
        final AsymmetricKeyParameter publicKey = keyPair.getPublic();

        encryptEngine = new RSAEngine();
        encryptEngine.init(true, publicKey); // true for encryption

        decryptEngine = new RSAEngine();
        decryptEngine.init(false, privateKey); // false for decryption
    }

    private byte[] encryptRsa(byte[] data) throws InvalidCipherTextException {
        return encryptEngine.processBlock(data, 0, data.length);
    }

    private byte[] decryptRsa(byte[] encryptedBytes) throws InvalidCipherTextException {
        return decryptEngine.processBlock(encryptedBytes, 0, encryptedBytes.length);
    }

    private byte[] encryptAes(byte[] data, byte[] key, byte[] initVector) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException {
        encryptCipherAes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(initVector));
        return encryptCipherAes.doFinal(data);
    }

    private byte[] decryptAes(byte[] encryptedData, byte[] key, byte[] initVector) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException {
        decryptCipherAes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(initVector));
        return decryptCipherAes.doFinal(encryptedData);
    }

    @Override
    public String getAlgorithmName() {
        return "Bouncy Castle RSA AES (OpenPGP)";
    }

    @Override
    public void run(String text) throws Exception {
        byte[] iv = ivKeyGenerator.generateKey().getEncoded();

        byte[] plainText = text.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessage = encryptAes(plainText, secretKey, iv);
        byte[] encryptedIv = encryptRsa(iv);

        byte[] decryptedIv = decryptRsa(encryptedIv);
        byte[] decryptedMessageBytes = decryptAes(encryptedMessage, secretKey, decryptedIv);
        String decryptedMessage = new String(decryptedMessageBytes);

        if (!decryptedMessage.equals(text)) {
            throw new AssertionError("Message not match");
        }
    }
}
