package me.ntsd.javacryptographybenchmark.benchmark;

import me.ntsd.javacryptographybenchmark.benchmark.BenchmarkAlgorithm;
import me.ntsd.javacryptographybenchmark.cryptography.JavaAes;
import me.ntsd.javacryptographybenchmark.cryptography.JavaRsa;

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

    private JavaAes javaAes;
    private byte[] secretKey;

    private JavaRsa javaRsa;

    public JavaRsaAndAesBenchmark() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        javaAes = new JavaAes();
        secretKey = javaAes.getAesKeyGenerator().generateKey().getEncoded();

        javaRsa = new JavaRsa();
    }

    @Override
    public String getAlgorithmName() {
        return "Javax Crypto RSA AES (OpenPGP)";
    }

    public void run(String text) throws Exception {
        byte[] iv = javaAes.getIvGenerator().generateKey().getEncoded();
        byte[] encryptedBytes = javaAes.encrypt(text.getBytes(StandardCharsets.UTF_8), secretKey, iv);
        byte[] encryptedIv = javaRsa.encrypt(iv);

        byte[] decryptedIv = javaRsa.decrypt(encryptedIv);
        String decryptedMessage = new String(javaAes.decrypt(encryptedBytes, secretKey, decryptedIv));

        if (!decryptedMessage.equals(text)) {
            throw new AssertionError("Message not match");
        }
    }
}
