package me.ntsd.bouncycastlebenchmark.encryption;

import me.ntsd.bouncycastlebenchmark.benchmark.BenchmarkAlgorithm;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
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

    public JavaRsaAndAesBenchmark() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        // AES Init
        ivGen = KeyGenerator.getInstance("AES"); // AES 128 bit
        ivGen.init(128); // iv is 128 bits

        encryptCipherAes = Cipher.getInstance("AES");
        decryptCipherAes = Cipher.getInstance("AES");

        // RSA Init
        KeyPair keyPair = buildKeyPair();
        final PublicKey publicKey = keyPair.getPublic();
        final PrivateKey privateKey = keyPair.getPrivate();

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

    private byte[] encryptRsa(byte[] message) throws BadPaddingException, IllegalBlockSizeException {
        return encryptCipherRsa.doFinal(message);
    }

    private byte[] decryptRsa(byte[] encrypted) throws BadPaddingException, IllegalBlockSizeException {
        return decryptCipherRsa.doFinal(encrypted);
    }

    private byte[] encryptAes(byte[] data, byte[] key) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        encryptCipherAes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return encryptCipherAes.doFinal(data);
    }

    private String decryptAes(byte[] encryptedData, byte[] key) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        decryptCipherAes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
        byte[] decValue = decryptCipherAes.doFinal(encryptedData);
        return new String(decValue);
    }

    @Override
    public String getAlgorithmName() {
        return "Javax Crypto RSA AES (OpenPGP)";
    }

    public void run(String text) throws Exception {
        byte[] iv = ivGen.generateKey().getEncoded();
        byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessage = encryptAes(textBytes, iv);
        byte[] encryptedIv = encryptRsa(iv);

        byte[] decryptedIv = decryptRsa(encryptedIv);
        String decryptedMessage = decryptAes(encryptedMessage, decryptedIv);

        if (!decryptedMessage.equals(text)) {
            throw new AssertionError("not match");
        }
    }
}
