// Test case: cryptographic-failures (A02:2025)
import java.security.MessageDigest;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class UserVault {

    // BUG: hardcoded encryption key committed to source
    private static final byte[] KEY = "hardcoded-key-16".getBytes();

    public static String hashPassword(String password) throws Exception {
        // BUG: MD5 is broken and unsalted — trivially reversed via rainbow tables
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes("UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static String generateResetToken() {
        // BUG: java.util.Random is not cryptographically secure (use SecureRandom)
        Random rng = new Random();
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            token.append(Integer.toHexString(rng.nextInt(16)));
        }
        return token.toString();
    }

    public static byte[] encrypt(byte[] plaintext) throws Exception {
        SecretKeySpec spec = new SecretKeySpec(KEY, "AES");
        // BUG: ECB mode leaks plaintext patterns — identical blocks encrypt identically
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, spec);
        return cipher.doFinal(plaintext);
    }
}
