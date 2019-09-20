package me.ntsd.javacryptographybenchmark.encryption;

import me.ntsd.javacryptographybenchmark.benchmark.BenchmarkAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;


public class BouncyCastleAesBenchmark implements BenchmarkAlgorithm {

    private KeyGenerator ivKeyGenerator;
    private byte[] secretKey;

    private Cipher encryptCipherAes;
    private Cipher decryptCipherAes;

    public BouncyCastleAesBenchmark() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());

        KeyGenerator aesKeyGenerator = KeyGenerator.getInstance("AES", "BC");
        aesKeyGenerator.init(128);  // AES 128 bit
        secretKey = aesKeyGenerator.generateKey().getEncoded();

        ivKeyGenerator = KeyGenerator.getInstance("AES", "BC");
        ivKeyGenerator.init(128); // iv is 128 bits

        encryptCipherAes = Cipher.getInstance("AES", "BC");
        decryptCipherAes = Cipher.getInstance("AES", "BC");
    }

    private byte[] encryptAes(byte[] data, byte[] key, byte[] initVector) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException {
        encryptCipherAes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(initVector));
        return encryptCipherAes.doFinal(data);
    }

    private byte[] decryptAes(byte[] encryptedData, byte[] key, byte[] initVector) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException {
        decryptCipherAes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(initVector));
        return decryptCipherAes.doFinal(encryptedData);
    }

    @Override
    public void run(String text) throws Exception {
        byte[] iv = ivKeyGenerator.generateKey().getEncoded();

        byte[] encryptedMessage = encryptAes(text.getBytes(StandardCharsets.UTF_8), secretKey, iv);

        String decryptedMessage = new String(decryptAes(encryptedMessage, secretKey, iv));

        if (!decryptedMessage.equals(text)) {
            throw new AssertionError("Message not match");
        }
    }

    @Override
    public String getAlgorithmName() {
        return "Bouncy Castle AES";
    }
}
