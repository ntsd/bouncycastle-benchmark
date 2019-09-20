package me.ntsd.bouncycastlebenchmark.encryption;


import me.ntsd.bouncycastlebenchmark.benchmark.BenchmarkAlgorithm;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;


public class JavaRsaAndAesBenchmark implements BenchmarkAlgorithm {

    private KeyGenerator ivGen;

    private Cipher encryptCipherRsa;
    private Cipher decryptCipherRsa;

    private Cipher encryptCipherAes;
    private Cipher decryptCipherAes;


    public JavaRsaAndAesBenchmark() throws Exception {
        // AES Init
        ivGen = KeyGenerator.getInstance("AES"); // AES 128 bit
        ivGen.init(128); // iv is 128 bits

        encryptCipherAes = Cipher.getInstance("AES");
        decryptCipherAes = Cipher.getInstance("AES");

        // RSA Init
        KeyPair keyPair = buildKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        encryptCipherRsa = Cipher.getInstance("RSA");
        encryptCipherRsa.init(Cipher.ENCRYPT_MODE, publicKey);

        decryptCipherRsa = Cipher.getInstance("RSA");
        decryptCipherRsa.init(Cipher.DECRYPT_MODE, privateKey);
    }

    private static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
        final int keySize = 1024;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    private byte[] encryptRsa(byte[] message) throws Exception {
        return encryptCipherRsa.doFinal(message);
    }

    private byte[] decryptRsa(byte[] encrypted) throws Exception {
        return decryptCipherRsa.doFinal(encrypted);
    }

    private String encryptAes(byte[] data, byte[] key) throws Exception {
        encryptCipherAes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        byte[] encVal = encryptCipherAes.doFinal(data);
        return new BASE64Encoder().encode(encVal);
    }

    private String decryptAes(String encryptedData, byte[] key) throws Exception {
        decryptCipherAes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
        byte[] decodedValue = new BASE64Decoder().decodeBuffer(encryptedData);
        byte[] decValue = decryptCipherAes.doFinal(decodedValue);
        return new String(decValue);
    }

    @Override
    public String getAlgorithmName() {
        return "Javax Crypto RSA AES (OpenPGP)";
    }

    public void run(String text) throws Exception {
        byte[] iv = ivGen.generateKey().getEncoded();

        byte[] plainText = text.getBytes(StandardCharsets.UTF_8);

        String encryptedMessage = encryptAes(plainText, iv);

        byte[] encryptedIv = encryptRsa(iv);

        byte[] decryptedIV = decryptRsa(encryptedIv);

        String decryptedMessage = decryptAes(encryptedMessage, decryptedIV);

        if (!decryptedMessage.equals(text)) {
            throw new Exception("not match");
        }
    }
}
