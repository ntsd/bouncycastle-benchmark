package me.ntsd.javacryptographybenchmark.benchmark;

import me.ntsd.javacryptographybenchmark.cryptography.BouncyCastleAesWithIv;

import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


public class BouncyCastleAesWithIvBenchmark implements BenchmarkAlgorithm {

    private BouncyCastleAesWithIv bouncyCastleAes;
    private byte[] secretKey;

    public BouncyCastleAesWithIvBenchmark() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        bouncyCastleAes = new BouncyCastleAesWithIv();

        secretKey = bouncyCastleAes.getAesKeyGenerator().generateKey().getEncoded();
    }

    @Override
    public String getAlgorithmName() {
        return "Bouncy Castle AES";
    }

    @Override
    public void run(String text) throws Exception {
        byte[] iv = bouncyCastleAes.getAesKeyGenerator().generateKey().getEncoded();
        byte[] encryptedBytes = bouncyCastleAes.encryptWithIv(text.getBytes(StandardCharsets.UTF_8), secretKey, iv);

        String decryptedMessage = new String(bouncyCastleAes.decryptWithIv(encryptedBytes, secretKey, iv));

        if (!decryptedMessage.equals(text)) {
            throw new AssertionError("Message not match");
        }
    }
}
