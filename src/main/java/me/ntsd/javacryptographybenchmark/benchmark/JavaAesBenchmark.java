package me.ntsd.javacryptographybenchmark.benchmark;

import me.ntsd.javacryptographybenchmark.cryptography.JavaAesWithIv;

import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


public class JavaAesBenchmark implements BenchmarkAlgorithm {

    private JavaAesWithIv javaAesWithIv;
    private byte[] secretKey;

    public JavaAesBenchmark() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        javaAesWithIv = new JavaAesWithIv();

        secretKey = javaAesWithIv.getAesKeyGenerator().generateKey().getEncoded();
    }

    @Override
    public String getAlgorithmName() {
        return "Javax Crypto AES";
    }

    @Override
    public void run(String text) throws Exception {
        byte[] iv = javaAesWithIv.getAesKeyGenerator().generateKey().getEncoded();
        byte[] encryptedBytes = javaAesWithIv.encryptWithIv(text.getBytes(StandardCharsets.UTF_8), secretKey, iv);

        String decryptedMessage = new String(javaAesWithIv.decryptWithIv(encryptedBytes, secretKey, iv));

        if (!decryptedMessage.equals(text)) {
            throw new AssertionError("Message not match");
        }
    }
}
