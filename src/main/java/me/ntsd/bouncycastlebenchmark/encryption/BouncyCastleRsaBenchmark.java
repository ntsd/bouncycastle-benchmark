package me.ntsd.bouncycastlebenchmark.encryption;

import me.ntsd.bouncycastlebenchmark.benchmark.BenchmarkAlgorithm;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;


public class BouncyCastleRsaBenchmark implements BenchmarkAlgorithm {

    private AsymmetricBlockCipher privateEngine;
    private AsymmetricBlockCipher publicEngine;

    private static AsymmetricCipherKeyPair GenerateKeys() throws NoSuchAlgorithmException {
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(new RSAKeyGenerationParameters(
                new BigInteger("10001", 16), //publicExponent
                SecureRandom.getInstance("SHA1PRNG"), //pseudorandom number generator
                1024, //strength
                80 //certainty
        ));

        return generator.generateKeyPair();
    }

    public BouncyCastleRsaBenchmark() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());

        // RSA Init
        AsymmetricCipherKeyPair keyPair = GenerateKeys();
        AsymmetricKeyParameter privateKey = keyPair.getPrivate();
        AsymmetricKeyParameter publicKey = keyPair.getPublic();

        privateEngine = new RSAEngine();
        privateEngine.init(false, privateKey); //false for decryption

        publicEngine = new RSAEngine();
        publicEngine.init(false, publicKey); //false for decryption
    }

    private static String getHexString(byte[] b) throws Exception {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private String encryptRsa(byte[] data) throws Exception {
        byte[] hexEncodedCipher = publicEngine.processBlock(data, 0, data.length);

        return getHexString(hexEncodedCipher);
    }

    private String decryptRsa(String encrypted) throws InvalidCipherTextException {
        byte[] encryptedBytes = hexStringToByteArray(encrypted);
        byte[] hexEncodedCipher = privateEngine.processBlock(encryptedBytes, 0, encryptedBytes.length);

        return new String(hexEncodedCipher);
    }

    @Override
    public String getAlgorithmName() {
        return "Bouncy Castle RSA";
    }

    @Override
    public void run(String text) throws Exception {
        String encryptedMessage = encryptRsa(text.getBytes());
        String decryptedMessage = decryptRsa(encryptedMessage);
    }
}
