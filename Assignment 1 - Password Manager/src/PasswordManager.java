import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
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
        } else {
            validatePassword(userPassword);
        }
        String saltString = getSaltString();
        SecretKey key = deriveKey(userPassword, saltString);
        while(true) {
            System.out.println("a : Add Password");
            System.out.println("r : Read Password");
            System.out.println("q : Quit");
            System.out.print("Enter Choice: ");
            String mode = scanner.nextLine();

            switch (mode) {
                case "a" -> addPassword(key);
                case "r" -> getPassword(key);
                case "q" -> {System.out.println("Quitting"); System.exit(0);}
                default -> System.out.println("Invalid input");
            }
            System.out.println();
        }
    }


    // gets salt stored in password file
    private String getSaltString() throws Exception {
        Scanner scanner = new Scanner(passwordFile);
        return scanner.nextLine().split(":")[0];
    }

    // gets has stored in password file
    private String getHash() throws Exception {
        Scanner scanner = new Scanner(passwordFile);
        return scanner.nextLine().split(":")[1];
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

    // this handles the adding new passwords
    private void addPassword(SecretKey key) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter label for password: ");
        String label = scanner.nextLine();
        System.out.print("Enter password to store: ");
        String password = scanner.nextLine();
        String encryptedPassword = encrypt(password, key);

        // remove existing entry
        File tempFile = new File(passwordFile.getAbsolutePath() + ".tmp");
        BufferedReader reader = new BufferedReader(new FileReader(passwordFile));
        BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile));
        String currentLine = reader.readLine();
        while(currentLine != null) {
            currentLine = currentLine.trim();
            String nextline = reader.readLine();
            if (currentLine.split(":")[0].equals(label)){
                currentLine = nextline;
                continue;
            }
            if (nextline == null) {
                writer.write(currentLine);
                currentLine = nextline;
                continue;
            }
            writer.write(currentLine+System.lineSeparator());
            currentLine = nextline;
        }
        if (passwordFile.delete()) {
            tempFile.renameTo(passwordFile);
        } else {
            System.out.println("could not properly add new password");
            System.exit(1);
        }
        writer.close();

        // add entry
        FileWriter fr = new FileWriter(passwordFile, true);
        fr.write(System.lineSeparator() + label+":"+encryptedPassword);
        fr.close();
    }

    private void getPassword(SecretKey key) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter label for password: ");
        String label = scanner.nextLine();
        try {
            String encryptedPassword = getCiperFromLabel(label);
            String decryptedPassword = decrypt(encryptedPassword, key);
            System.out.println("Found: " + decryptedPassword);
        } catch (Exception e) {
            System.out.println("Error, label not found");
        }
    }

    // finds the text associated with a label
    private String getCiperFromLabel(String label) throws Exception {
        Scanner scanner = new Scanner(passwordFile);
        scanner.nextLine();
        while (scanner.hasNext()) {
            String currLine = scanner.nextLine();
            String currLabel = currLine.split(":")[0];
            if (currLabel.equals(label)) {
                return currLine.split(":")[1];
            }
        }
        throw new Exception();
    }

    private void validatePassword(String password) throws Exception{
        String storedHash = getHash();
        String storedSalt = getSaltString();
        String inputHash = generateHash(password, storedSalt);
        if (!storedHash.equals(inputHash)) {
            System.out.println("Invalid Password");
            System.exit(0);
        }
    }

    public static void main(String[] args) throws Exception {



        PasswordManager pm = new PasswordManager();
        pm.promtUser();
    }
}
