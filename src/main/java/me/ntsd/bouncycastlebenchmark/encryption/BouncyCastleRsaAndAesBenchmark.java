package me.ntsd.bouncycastlebenchmark.encryption;

import me.ntsd.bouncycastlebenchmark.benchmark.BenchmarkAlgorithm;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;


public class BouncyCastleRsaAndAesBenchmark implements BenchmarkAlgorithm {

    private byte[] password;
    private KeyGenerator ivGen;

    private PaddedBufferedBlockCipher encryptCipherAes;
    private PaddedBufferedBlockCipher decryptCipherAes;

    private AsymmetricBlockCipher encryptEngine;
    private AsymmetricBlockCipher decryptEngine;

    private AsymmetricCipherKeyPair generateKeys() {
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(new RSAKeyGenerationParameters(
            BigInteger.valueOf(0x10001), // public exponent
            new SecureRandom(), // random number generator
            1024, // key size
            80 // certainty
        ));

        return generator.generateKeyPair();
    }

    public BouncyCastleRsaAndAesBenchmark() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        // AES Init
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // key is 128 bits
        password = keyGen.generateKey().getEncoded();

        ivGen = KeyGenerator.getInstance("AES");
        ivGen.init(128); // iv is 128 bits

        encryptCipherAes = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        decryptCipherAes = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

        // RSA Init
        AsymmetricCipherKeyPair keyPair = generateKeys();
        AsymmetricKeyParameter privateKey = keyPair.getPrivate();
        AsymmetricKeyParameter publicKey = keyPair.getPublic();

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

    private byte[] cipherData(PaddedBufferedBlockCipher cipher, byte[] data) throws Exception {
        byte[] outputBuffer = new byte[cipher.getOutputSize(data.length)];

        int length1 = cipher.processBytes(data,  0, data.length, outputBuffer, 0);
        int length2 = cipher.doFinal(outputBuffer, length1);

        byte[] result = new byte[length1 + length2];

        System.arraycopy(outputBuffer, 0, result, 0, result.length);

        return result;
    }

    private byte[] encryptAes(byte[] plain, CipherParameters ivAndKey) throws Exception {
        encryptCipherAes.init(true, ivAndKey);

        return cipherData(encryptCipherAes, plain);
    }

    private byte[] decryptAes(byte[] cipher, CipherParameters ivAndKey) throws Exception {
        decryptCipherAes.init(false,  ivAndKey);

        return cipherData(decryptCipherAes, cipher);
    }

    @Override
    public String getAlgorithmName() {
        return "Bouncy Castle RSA AES (OpenPGP)";
    }

    @Override
    public void run(String text) throws Exception {
        byte[] iv = ivGen.generateKey().getEncoded();

        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(password), iv);

        byte[] plainText = text.getBytes(StandardCharsets.UTF_8);

        byte[] encryptedMessage = encryptAes(plainText, ivAndKey);

        byte[] encryptedIv = encryptRsa(iv);

        byte[] decryptedIV = decryptRsa(encryptedIv);

        CipherParameters ivAndKey2 = new ParametersWithIV(new KeyParameter(password), decryptedIV);

        byte[] decryptedMessageBytes = decryptAes(encryptedMessage, ivAndKey2);

        String decryptedMessage = new String(decryptedMessageBytes);

        if (!decryptedMessage.equals(text)) {
            throw new Exception("not match");
        }
    }
}
