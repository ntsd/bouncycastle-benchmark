package me.ntsd.bouncycastlebenchmark.encryption;

import me.ntsd.bouncycastlebenchmark.benchmark.BenchmarkAlgorithm;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;


public class JavaRsaAndAesBenchmark implements BenchmarkAlgorithm {

    private KeyGenerator ivGen;
    private byte[] secretKey;
    private Cipher encryptCipherAes;
    private Cipher decryptCipherAes;

    private Cipher encryptCipherRsa;
    private Cipher decryptCipherRsa;

    public JavaRsaAndAesBenchmark() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        // AES Init
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        secretKey = keyGen.generateKey().getEncoded();

        ivGen = KeyGenerator.getInstance("AES"); // AES 128 bit
        ivGen.init(128); // iv is 128 bits

        encryptCipherAes = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        decryptCipherAes = Cipher.getInstance("AES/CBC/PKCS5PADDING");

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
        return "Javax Crypto RSA AES (OpenPGP)";
    }

    public void run(String text) throws Exception {
        byte[] iv = ivGen.generateKey().getEncoded();
        byte[] encryptedMessage = encryptAes(text.getBytes(StandardCharsets.UTF_8), secretKey, iv);
        byte[] encryptedIv = encryptRsa(iv);

        byte[] decryptedIv = decryptRsa(encryptedIv);
        String decryptedMessage = new String(decryptAes(encryptedMessage, secretKey, decryptedIv));

        if (!decryptedMessage.equals(text)) {
            throw new AssertionError("Message not match");
        }
    }
}
