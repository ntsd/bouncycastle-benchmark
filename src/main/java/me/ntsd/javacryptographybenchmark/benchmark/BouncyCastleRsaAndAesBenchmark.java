package me.ntsd.javacryptographybenchmark.benchmark;

import me.ntsd.javacryptographybenchmark.cryptography.BouncyCastleAes;
import me.ntsd.javacryptographybenchmark.cryptography.BouncyCastleRsa;

import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


public class BouncyCastleRsaAndAesBenchmark implements BenchmarkAlgorithm {

    private BouncyCastleAes bouncyCastleAes;
    private BouncyCastleRsa bouncyCastleRsa;

    public BouncyCastleRsaAndAesBenchmark() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {
        bouncyCastleAes = new BouncyCastleAes();
        bouncyCastleRsa = new BouncyCastleRsa();
    }

    @Override
    public String getAlgorithmName() {
        return "Bouncy Castle RSA & Java AES (PGP)";
    }

    @Override
    public void run(String text) throws Exception {
        byte[] iv = bouncyCastleAes.getAesKeyGenerator().generateKey().getEncoded();
        byte[] encryptedBytes = bouncyCastleAes.encrypt(text.getBytes(StandardCharsets.UTF_8), iv);
        byte[] encryptedIv = bouncyCastleRsa.encrypt(iv);

        byte[] decryptedIv = bouncyCastleRsa.decrypt(encryptedIv);
        String decryptedMessage = new String(bouncyCastleAes.decrypt(encryptedBytes, decryptedIv));

        if (!decryptedMessage.equals(text)) {
            throw new AssertionError("Message not match");
        }
    }
}
