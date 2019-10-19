import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;


public class GenerateKeys {
    //Lista użtykwoników do wygenerowania
    public static final String[] RECEIVERS = {"Jan Kowalski",
        "Malwina Ekler", "Gal Anonim", "Bill Gates", "Anna Nowak", 
        "Olaf Nowy", "Ewelina Pasibrzuch", "Joanna Damecka", 
        "Krzysztof Kowal", "Weronika Ostap"};
    
    public static final String ALGORITHM = "AES";
    // Hasło do klucza prywatnego
    public static final String PASSWORD = "password";

     public static void savePublicKey(String user, String modulus, 
             String exponent, String publicKeyFileUrl) throws ParserConfigurationException, TransformerException, FileNotFoundException {
        Document dom;
        Element e = null;
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbFactory.newDocumentBuilder();
            dom = db.newDocument();
            Element root = dom.createElement("RSAKey");
            e = dom.createElement("user");
            e.appendChild(dom.createTextNode(user));
            root.appendChild(e);
            e = dom.createElement("modulus");
            e.appendChild(dom.createTextNode(modulus));
            root.appendChild(e);
            e = dom.createElement("exponent");
            e.appendChild(dom.createTextNode(exponent));
            root.appendChild(e);
            dom.appendChild(root);

            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.transform(new DOMSource(dom), new StreamResult(new FileOutputStream(publicKeyFileUrl)));

    }
     
    public static void generateKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, ParserConfigurationException, TransformerException {
        for (String receiver : RECEIVERS) {

                String privateKeyFileUrl = receiver + ".priv";
                String publicKeyFileUrl = receiver + ".pub";
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(1024);
                KeyPair key = keyGen.genKeyPair();
                PublicKey publicKey = key.getPublic();
                PrivateKey privateKey = key.getPrivate();

                // Get the formats of the encoded bytes
                String formatPrivate = privateKey.getFormat(); // PKCS#8
                String formatPublic = publicKey.getFormat(); // X.509
                System.out.println(formatPrivate);
                System.out.println(formatPublic);

                // Save public key
                KeyFactory fact = KeyFactory.getInstance("RSA");
                RSAPublicKeySpec publicKeySpec = fact.getKeySpec(publicKey, RSAPublicKeySpec.class);
                String modulus = Base64.getEncoder().encodeToString(publicKeySpec.getModulus().toByteArray());
                String exponent = Base64.getEncoder().encodeToString(publicKeySpec.getPublicExponent().toByteArray());
                savePublicKey(receiver, modulus, exponent, publicKeyFileUrl);
                
                // Create file private key
                File privateKeyFile = new File(privateKeyFileUrl);
                privateKeyFile.createNewFile();
                // Hash (MD5) of password to Private key
                MessageDigest mD = MessageDigest.getInstance("MD5");
                byte[] passMd5 = mD.digest(PASSWORD.getBytes());
                // Encrypt Private key


                SecretKey secretKey = new SecretKeySpec(passMd5, "DES");
                byte[] rsaKey = privateKey.getEncoded();
                Cipher cipher2Fish = Cipher.getInstance("Twofish","BC");
                cipher2Fish.init(Cipher.ENCRYPT_MODE, secretKey);
                byte[] encryptedRsaKey = cipher2Fish.doFinal(rsaKey);
                // Saving the Private key in a file      
                FileOutputStream fos = new FileOutputStream(privateKeyFile);
                fos.write(encryptedRsaKey, 0, encryptedRsaKey.length);
                fos.flush();
                fos.close();


        }
    }

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException, TransformerException, ParserConfigurationException {
        Security.addProvider(new BouncyCastleProvider());
        generateKey();
        System.out.println("Klucze zostały wygenerowane.");
    }
}
