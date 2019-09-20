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
    private AsymmetricKeyParameter privateKey;
    private AsymmetricKeyParameter publicKey;
    private KeyGenerator ivGen;

    private RSAEngine encryptEngine;
    private AsymmetricBlockCipher decryptEngine;

    private static AsymmetricCipherKeyPair generateKeys() throws NoSuchAlgorithmException {
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(new RSAKeyGenerationParameters(
                new BigInteger("10001", 16), // publicExponent
                SecureRandom.getInstance("SHA1PRNG"), // pseudorandom number generator
                1024, // strength
                80 // certainty
        ));

        return generator.generateKeyPair();
    }

    public BouncyCastleRsaAndAesBenchmark() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        // AES Init
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // key is 256 bits
        password = keyGen.generateKey().getEncoded();

        ivGen = KeyGenerator.getInstance("AES");
        ivGen.init(128); // iv is 128 bits

        // RSA Init
        AsymmetricCipherKeyPair keyPair = generateKeys();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

        encryptEngine = new RSAEngine();
        decryptEngine = new RSAEngine();
    }

    private static String getHexString(byte[] b) {
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

    private String encryptRsa(byte[] data, AsymmetricKeyParameter publicKey) {
        encryptEngine.init(true, publicKey); // true if encrypt

        byte[] hexEncodedCipher = encryptEngine.processBlock(data, 0, data.length);

        return getHexString(hexEncodedCipher);
    }

    private byte[] decryptRsa(String encrypted, AsymmetricKeyParameter privateKey) throws InvalidCipherTextException {
        decryptEngine.init(false, privateKey); // false for decryption

        byte[] encryptedBytes = hexStringToByteArray(encrypted);
        byte[] hexEncodedCipher = decryptEngine.processBlock(encryptedBytes, 0, 128);

        return hexEncodedCipher;
    }

    private static byte[] cipherData(PaddedBufferedBlockCipher cipher, byte[] data) throws Exception {
        byte[] outputBuffer = new byte[cipher.getOutputSize(data.length)];

        int length1 = cipher.processBytes(data,  0, data.length, outputBuffer, 0);
        int length2 = cipher.doFinal(outputBuffer, length1);

        byte[] result = new byte[length1 + length2];

        System.arraycopy(outputBuffer, 0, result, 0, result.length);

        return result;
    }

    private static byte[] encryptAes(byte[] plain, CipherParameters ivAndKey) throws Exception {
        PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(
                new CBCBlockCipher(
                        new AESEngine()
                )
        );

        aes.init(true, ivAndKey);

        return cipherData(aes, plain);

    }

    private static byte[] decryptAes(byte[] cipher, CipherParameters ivAndKey) throws Exception {
        PaddedBufferedBlockCipher aes2 = new PaddedBufferedBlockCipher(
                new CBCBlockCipher(
                        new AESEngine()
                )
        );
        aes2.init(false,  ivAndKey);

        return cipherData(aes2, cipher);
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

        String encryptedIv = encryptRsa(iv, publicKey);

        byte[] decryptedIV = decryptRsa(encryptedIv, privateKey);

        CipherParameters ivAndKey2 = new ParametersWithIV(new KeyParameter(password), decryptedIV);

        String decryptedMessage = new String(decryptAes(encryptedMessage, ivAndKey2));

        if (!decryptedMessage.equals(text)) {
            throw new Exception("not match");
        }
    }
}
