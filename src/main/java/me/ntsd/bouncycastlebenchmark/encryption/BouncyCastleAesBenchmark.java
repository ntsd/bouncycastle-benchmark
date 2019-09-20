package me.ntsd.bouncycastlebenchmark.encryption;

import me.ntsd.bouncycastlebenchmark.benchmark.BenchmarkAlgorithm;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Security;


public class BouncyCastleAesBenchmark implements BenchmarkAlgorithm {

    private byte[] password;
    private KeyGenerator ivGen;

    private PaddedBufferedBlockCipher encryptCipherAes;
    private PaddedBufferedBlockCipher decryptCipherAes;

    public BouncyCastleAesBenchmark() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // key is 128 bits
        password = keyGen.generateKey().getEncoded();

        ivGen = KeyGenerator.getInstance("AES");
        ivGen.init(128); // iv is 128 bits

        encryptCipherAes = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        decryptCipherAes = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
    }

    private byte[] cipherData(PaddedBufferedBlockCipher cipher, byte[] data) throws Exception {
        byte[] outputBuffer = new byte[cipher.getOutputSize(data.length)];

        int length1 = cipher.processBytes(data,  0, data.length, outputBuffer, 0);
        int length2 = cipher.doFinal(outputBuffer, length1);

        byte[] result = new byte[length1 + length2];

        System.arraycopy(outputBuffer, 0, result, 0, result.length);

        return result;
    }

    private byte[] encryptAes(byte[] plain, CipherParameters ivAndKey) throws Exception {
        encryptCipherAes.init(true, ivAndKey);

        return cipherData(encryptCipherAes, plain);
    }

    private byte[] decryptAes(byte[] cipher, CipherParameters ivAndKey) throws Exception {
        decryptCipherAes.init(false,  ivAndKey);

        return cipherData(decryptCipherAes, cipher);
    }

    @Override
    public void run(String text) throws Exception {
        byte[] iv = ivGen.generateKey().getEncoded();

        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(password), iv);

        byte[] plainText = text.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessage = encryptAes(plainText, ivAndKey);

        CipherParameters ivAndKey2 = new ParametersWithIV(new KeyParameter(password), iv);

        String decryptedMessage = new String(decryptAes(encryptedMessage, ivAndKey2));

        if (!decryptedMessage.equals(text)) {
            throw new Exception("not match");
        }
    }

    @Override
    public String getAlgorithmName() {
        return "Bouncy Castle AES";
    }
}
