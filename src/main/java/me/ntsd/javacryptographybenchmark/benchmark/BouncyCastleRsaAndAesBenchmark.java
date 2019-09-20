package me.ntsd.javacryptographybenchmark.benchmark;

import me.ntsd.javacryptographybenchmark.cryptography.BouncyCastleAes;
import me.ntsd.javacryptographybenchmark.cryptography.BouncyCastleRsa;

import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


public class BouncyCastleRsaAndAesBenchmark implements BenchmarkAlgorithm {

    private BouncyCastleAes bouncyCastleAes;
    private BouncyCastleRsa bouncyCastleRsa;
    private byte[] secretKey;

    public BouncyCastleRsaAndAesBenchmark() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        bouncyCastleAes = new BouncyCastleAes();
        bouncyCastleRsa = new BouncyCastleRsa();

        secretKey = bouncyCastleAes.getAesKeyGenerator().generateKey().getEncoded();
    }

    @Override
    public String getAlgorithmName() {
        return "Bouncy Castle RSA AES (OpenPGP)";
    }

    @Override
    public void run(String text) throws Exception {
        byte[] iv = bouncyCastleAes.getIvGenerator().generateKey().getEncoded();
        byte[] encryptedBytes = bouncyCastleAes.encrypt(text.getBytes(StandardCharsets.UTF_8), secretKey, iv);
        byte[] encryptedIv = bouncyCastleRsa.encrypt(iv);

        byte[] decryptedIv = bouncyCastleRsa.decrypt(encryptedIv);
        String decryptedMessage = new String(bouncyCastleAes.decrypt(encryptedBytes, secretKey, decryptedIv));

        if (!decryptedMessage.equals(text)) {
            throw new AssertionError("Message not match");
        }
    }
}
