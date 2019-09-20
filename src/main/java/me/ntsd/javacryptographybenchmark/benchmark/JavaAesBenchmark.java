package me.ntsd.javacryptographybenchmark.benchmark;

import me.ntsd.javacryptographybenchmark.cryptography.BouncyCastleAes;
import me.ntsd.javacryptographybenchmark.cryptography.JavaAes;

import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


public class JavaAesBenchmark implements BenchmarkAlgorithm {

    private JavaAes javaAes;
    private byte[] secretKey;

    public JavaAesBenchmark() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        javaAes = new JavaAes();

        secretKey = javaAes.getAesKeyGenerator().generateKey().getEncoded();
    }

    @Override
    public String getAlgorithmName() {
        return "Bouncy Castle AES";
    }

    @Override
    public void run(String text) throws Exception {
        byte[] iv = javaAes.getIvGenerator().generateKey().getEncoded();
        byte[] encryptedBytes = javaAes.encrypt(text.getBytes(StandardCharsets.UTF_8), secretKey, iv);

        String decryptedMessage = new String(javaAes.decrypt(encryptedBytes, secretKey, iv));

        if (!decryptedMessage.equals(text)) {
            throw new AssertionError("Message not match");
        }
    }
}
