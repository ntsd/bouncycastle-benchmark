package me.ntsd.javacryptographybenchmark.benchmark;

import me.ntsd.javacryptographybenchmark.cryptography.BouncyCastleRsa;

import java.nio.charset.StandardCharsets;


public class BouncyCastleRsaBenchmark implements BenchmarkAlgorithm {

    private BouncyCastleRsa bouncyCastleRsa;

    public BouncyCastleRsaBenchmark() {
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
