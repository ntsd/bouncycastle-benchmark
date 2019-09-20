package me.ntsd.javacryptographybenchmark.benchmark;

import me.ntsd.javacryptographybenchmark.cryptography.BouncyCastleAes;

import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


public class BouncyCastleAesBenchmark implements BenchmarkAlgorithm {

    private BouncyCastleAes bouncyCastleAes;
    private byte[] secretKey;

    public BouncyCastleAesBenchmark() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        bouncyCastleAes = new BouncyCastleAes();

        secretKey = bouncyCastleAes.getAesKeyGenerator().generateKey().getEncoded();
    }

    @Override
    public String getAlgorithmName() {
        return "Bouncy Castle AES";
    }

    @Override
    public void run(String text) throws Exception {
        byte[] iv = bouncyCastleAes.getIvGenerator().generateKey().getEncoded();
        byte[] encryptedBytes = bouncyCastleAes.encrypt(text.getBytes(StandardCharsets.UTF_8), secretKey, iv);

        String decryptedMessage = new String(bouncyCastleAes.decrypt(encryptedBytes, secretKey, iv));

        if (!decryptedMessage.equals(text)) {
            throw new AssertionError("Message not match");
        }
    }
}
