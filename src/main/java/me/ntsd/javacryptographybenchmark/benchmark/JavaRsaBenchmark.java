package me.ntsd.javacryptographybenchmark.benchmark;

import me.ntsd.javacryptographybenchmark.cryptography.JavaRsa;

import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


public class JavaRsaBenchmark implements BenchmarkAlgorithm {

    private JavaRsa javaRsa;

    public JavaRsaBenchmark() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        javaRsa = new JavaRsa();
    }

    @Override
    public String getAlgorithmName() {
        return "Javax Crypto RSA";
    }

    public void run(String text) throws Exception {
        byte[] encryptedBytes = javaRsa.encrypt(text.getBytes(StandardCharsets.UTF_8));

        String decryptedMessage = new String(javaRsa.decrypt(encryptedBytes));

        if (!decryptedMessage.equals(text)) {
            throw new AssertionError("Message not match");
        }
    }
}
