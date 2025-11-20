// Bad: Using weak cryptographic algorithms
import java.security.MessageDigest;

public void hashPassword(String password) {
    MessageDigest md = MessageDigest.getInstance("MD5");
    byte[] hash = md.digest(password.getBytes());
}
