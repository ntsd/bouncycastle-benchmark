package me.ntsd.bouncycastlebenchmark.encryption;

import me.ntsd.bouncycastlebenchmark.benchmark.BenchmarkAlgorithm;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;


public class JavaRsaBenchmark implements BenchmarkAlgorithm {

    private Cipher decryptCipher;

    private Cipher encryptCipher;

    public JavaRsaBenchmark() throws Exception {
        KeyPair keyPair = buildKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
    }

    private static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
        final int keySize = 1024;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    private byte[] encrypt(String message) throws Exception {
        return encryptCipher.doFinal(message.getBytes());
    }

    private byte[] decrypt(byte [] encrypted) throws Exception {
        return decryptCipher.doFinal(encrypted);
    }

    @Override
    public String getAlgorithmName() {
        return "Javax Crypto RSA";
    }

    public void run(String text) throws Exception {
        byte[] encryptedMessage = encrypt(text);
        String decryptedMessage = new String(decrypt(encryptedMessage));

        if (!decryptedMessage.equals(text)) {
            throw new Exception("not match");
        }
    }
}
