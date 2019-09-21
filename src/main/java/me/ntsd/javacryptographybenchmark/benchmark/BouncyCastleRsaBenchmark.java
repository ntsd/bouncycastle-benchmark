package me.ntsd.javacryptographybenchmark.benchmark;

import me.ntsd.javacryptographybenchmark.cryptography.BouncyCastleRsa;

import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


public class BouncyCastleRsaBenchmark implements BenchmarkAlgorithm {

    private BouncyCastleRsa bouncyCastleRsa;

    public BouncyCastleRsaBenchmark() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException {
        bouncyCastleRsa = new BouncyCastleRsa();
    }

    @Override
    public String getAlgorithmName() {
        return "Bouncy Castle RSA";
    }

    @Override
    public void run(String text) throws Exception {
        byte[] encryptedBytes = bouncyCastleRsa.encrypt(text.getBytes(StandardCharsets.UTF_8));

        String decryptedMessage = new String(bouncyCastleRsa.decrypt(encryptedBytes));

        if (!decryptedMessage.equals(text)) {
            throw new AssertionError("Message not match");
        }
    }
}
