import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileWriter;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

public class PasswordManager {
    private final File passwordFile = new File("password");
    private final int ITERATIONS = 600000;
    private final int KEY_LENGTH = 128;

    public void promtUser() throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the passcode to access your passwords: ");
        String userPassword = scanner.nextLine();
        if (!passwordFile.exists()) {
            System.out.println("No password file detected. Creating a new password file.");
            createPasswordFile(userPassword);
        }
        String saltString = getSaltString();
        SecretKey key = deriveKey(userPassword, saltString);
        System.out.println("a : Add Password");
        System.out.println("r : Read Password");
        System.out.println("q : Quit");
        System.out.print("Enter Choice: ");
        String mode = scanner.nextLine();
        System.out.println(decrypt(encrypt("asadf", key), key));

        switch (mode) {
            case "a":
                addPassword(key);
                break;
            case "r":
                getPassword(key);
                break;
            case "q":
                System.exit(0);
            default:
                System.out.println("Invalid input");
        }

    }

    private String getSaltString() throws Exception {
        Scanner scanner = new Scanner(passwordFile);
        return scanner.nextLine().split(":")[0];
    }

    // creates a new password file
    private void createPasswordFile(String password) throws Exception {
        String saltString = generateSaltString();
        String tokenString = generateHash(password, saltString);
        FileWriter myWriter = new FileWriter("password");
        myWriter.write(saltString + ":" + tokenString);
        myWriter.close();
     }

     // generates a new salt
    private String generateSaltString() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    // generates a PBKDF2 Hash from a password and salt
    private String generateHash(String password, String saltString) throws Exception {
        byte[] salt = Base64.getDecoder().decode(saltString);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] encoded = factory.generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }

    // generate a key from a password and salt
    private SecretKey deriveKey(String password, String saltString) throws Exception {
        byte[] salt = Base64.getDecoder().decode(saltString);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] encoded = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(encoded, "AES");
    }

    // takes a String and Key and returns the encrypted stuff :)
    private String encrypt(String encryptMe, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte [] encryptedData = cipher.doFinal(encryptMe.getBytes());
        return new String(Base64.getEncoder().encode(encryptedData));
    }

    // takes an encrypted string and key and returns clear text
    private String decrypt(String decryptMe, SecretKey key) throws Exception{
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte [] decoded = Base64.getDecoder().decode(decryptMe);
        byte [] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }

    private void addPassword(SecretKey key) {

    }

    private void getPassword(SecretKey key) {

    }





    // readPassword (label)

    // quitProgram()

    // login(password) --> gets the key

    // getSalt() --> gets the salt

    // getCipher(label)









    public static void main(String[] args) throws Exception {
        PasswordManager pm = new PasswordManager();
        pm.promtUser();
    }
}
