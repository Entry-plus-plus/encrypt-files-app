package twofishjavafx;

import com.thoughtworks.xstream.XStream;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.ListView;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MainController implements Initializable {

    @FXML
    private TextField textFieldChooseOutputFileEncryptMode;
    @FXML
    private ProgressBar progressBarDecryptMode;
    @FXML
    private CheckBox checkBoxShowPassword;
    @FXML
    private ListView<User> receiverListViewDecryptMode;
    @FXML
    private TextField textFiledChooseInputFileDecryptMode;
    @FXML
    private TextField textFieldChooseInputFileEncryptMode;
    @FXML
    private ComboBox<String> comboBoxEncryptMode;
    @FXML
    private ComboBox<String> comboBoxLenghtKey;
    @FXML
    private PasswordField passwordField;
    @FXML
    private TextField passwordText;
    @FXML
    private ComboBox<String> comboBoxLenghtSubBlock;
    @FXML
    private ProgressBar progressBarEncryptMode;
    @FXML
    private ListView<Receiver> receiverListViewEncryptMode;
    @FXML
    private Button buttonDecrypt;
    @FXML
    private TextField textFiledChooseOutputFileDecryptMode;

    private static final String receiversPath = System.getProperty("user.dir")
            + File.separator + "resources" + File.separator + "recivers";
    private static final String usersPath = System.getProperty("user.dir")
            + File.separator + "resources" + File.separator + "users";

    private static final ObservableList<String> encryptModeList
            = FXCollections.observableArrayList("ECB", "CBC", "CFB", "OFB");
    private static final ObservableList<String> keyLenghtList
            = FXCollections.observableArrayList("128", "192", "256");
    private static final ObservableList<String> subBlockLenghtList
            = FXCollections.observableArrayList("8", "16", "32", "64", "128");

    private final ObservableList<Receiver> receiverList = FXCollections.observableArrayList();
    private final ObservableList<User> userList = FXCollections.observableArrayList();

    private String password;
    private String encryptMode;
    private String keyLength;
    private String subBlockLength;
    private File fileToEncryptOutput;
    private File fileToEncryptInput;
    private File fileToDecryptOutput;
    private File fileToDecryptInput;
    private EncryptedFileHeader encryptedFileHeader;

    @Override
    public void initialize(URL url, ResourceBundle rb) {
        Security.addProvider(new BouncyCastleProvider());
        encryptMode = "CBC";
        keyLength = "128";
        subBlockLength = "-";
        password = "ITS BAD PASSWORD BUT BETTER THAN NULL";

        passwordText.setVisible(false);
        receiverListViewEncryptMode.setItems(receiverList);
        receiverListViewDecryptMode.setItems(userList);
        comboBoxEncryptMode.setItems(encryptModeList);
        comboBoxLenghtKey.setItems(keyLenghtList);
        comboBoxLenghtSubBlock.setItems(subBlockLenghtList);
        comboBoxLenghtSubBlock.setDisable(true);

        buttonDecrypt.setDisable(true);
        //Enable button decrypt when you are choice user
        receiverListViewDecryptMode.setOnMouseClicked(new EventHandler<MouseEvent>() {
            @Override
            public void handle(MouseEvent event) {
                if (receiverListViewDecryptMode.getSelectionModel().getSelectedItem() != null) {
                    buttonDecrypt.setDisable(false);
                } else {
                    buttonDecrypt.setDisable(true);
                }
            }
        });
    }

    @FXML
    void showPassword(ActionEvent event) {
        if (checkBoxShowPassword.isSelected() == true) {
            this.password = passwordField.getText();
            passwordText.setText(this.password);
            passwordText.setVisible(true);
            passwordField.setVisible(false);
        } else if (checkBoxShowPassword.isSelected() == false) {
            this.password = passwordText.getText();
            passwordField.setText(password);
            passwordText.setVisible(false);
            passwordField.setVisible(true);
        }
    }

    @FXML
    void encryptModeChooseInputFile(ActionEvent event) {
        FileChooser chooseFileToEncrypt = new FileChooser();
        fileToEncryptInput = chooseFileToEncrypt.showOpenDialog(null);
        if (fileToEncryptInput != null) {
            textFieldChooseInputFileEncryptMode.setText(fileToEncryptInput.getPath());
        }
    }

    @FXML
    void encryptModeChooseOutputFile(ActionEvent event) {
        FileChooser chooseOutputEncryptFilePath = new FileChooser();
        fileToEncryptOutput = chooseOutputEncryptFilePath.showSaveDialog(null);
        if (fileToEncryptOutput != null) {
            textFieldChooseOutputFileEncryptMode.setText(fileToEncryptOutput.getPath());
        }
    }

    @FXML
    void encryptModeAddReceiver(ActionEvent event) {
        FileChooser chooseReceiver = new FileChooser();
        chooseReceiver.getExtensionFilters().addAll(
                new ExtensionFilter("Public key", "*.pub"));
        File workingDirectory = new File(receiversPath);
        chooseReceiver.setInitialDirectory(workingDirectory);
        List<File> listOfFiles = chooseReceiver.showOpenMultipleDialog(null);
        if (listOfFiles != null) {
            for (File receiverFromPublicKeyFile : listOfFiles) {
                if (receiverFromPublicKeyFile != null) {
                    //Add receiver to list
                    String name = receiverFromPublicKeyFile.getName();
                    name = name.substring(0, name.length() - 4);    //delete extension from file name
                    PublicKey publicKey = readPublicKeyFromFile(receiverFromPublicKeyFile);

                    Receiver newReceiver = new Receiver(name, publicKey);
                    boolean find = false;
                    for (Receiver receiver : receiverList) {
                        if (newReceiver.getName().equals(receiver.getName())) {
                            find = true;
                            break;
                        }
                    }
                    if (find == false) {
                        receiverList.add(newReceiver);
                    }
                }
            }
        }
    }

    private PublicKey readPublicKeyFromFile(File publicKeyFile) {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder;
        Document doc = null;
        PublicKey publicKey = null;
        try {
            dBuilder = dbFactory.newDocumentBuilder();
            doc = dBuilder.parse(publicKeyFile);
            doc.getDocumentElement().normalize();
        } catch (ParserConfigurationException | SAXException | IOException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
        }
        NodeList nList = doc.getElementsByTagName("modulus");
        String modulus = readNodeFromXml(nList);
        nList = doc.getElementsByTagName("exponent");
        String exponent = readNodeFromXml(nList);
        // Load the key into BigIntegers
        BigInteger modulusBigInteger = new BigInteger(Base64.getDecoder().decode(modulus));
        BigInteger exponentBigInteger = new BigInteger(Base64.getDecoder().decode(exponent));
        RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(modulusBigInteger, exponentBigInteger);
        // Create a key
        KeyFactory factory;
        try {
            factory = KeyFactory.getInstance("RSA");
            publicKey = factory.generatePublic(publicSpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
        }
        return publicKey;
    }

    private String readNodeFromXml(NodeList nList) {
        String tmp = null;
        for (int temp = 0; temp < nList.getLength(); temp++) {
            Node nNode = nList.item(temp);
            if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                Element eElement = (Element) nNode;
                tmp = eElement.getTextContent();
            }
        }
        return tmp;
    }

    @FXML
    void encryptModeDeleteReceiver(ActionEvent event) {
        Receiver receiverToDelete
                = receiverListViewEncryptMode.getSelectionModel().getSelectedItem();
        if (receiverToDelete != null) {
            receiverList.remove(receiverToDelete);
        }
    }

    @FXML
    void chooseEncryptFileMode(ActionEvent event) {
        if (comboBoxEncryptMode.getValue().equals(encryptModeList.get(2))
                || comboBoxEncryptMode.getValue().equals(encryptModeList.get(3))) {
            comboBoxLenghtSubBlock.setDisable(false);
        } else {
            comboBoxLenghtSubBlock.setDisable(true);
        }
    }

    @FXML
    void encryptFile(ActionEvent event) {
        if (receiverList.isEmpty() == false && fileToEncryptInput.exists()
                && fileToEncryptOutput.toPath() != null) {
            //Table because needs return 2 arguments
            SecureRandom secureRandom = null;
            SecureRandom[] secureRandoms = {secureRandom};
            SecretKey secretKey = generateSessionKey(secureRandoms);
            secureRandom = secureRandoms[0];

            readValueFromComboBox();
            //Prepare encrypt                     
            String command = createCommandToEncrypt();
            Cipher cipher = initializeCipherToEncrypt(command, secretKey, secureRandom);
            byte[] initializationVectorBytes = setInitializationVector(cipher);

            //Prepare to save as xml
            EncryptedFileHeader encryptFileHeader = new EncryptedFileHeader(
                    "Twofish", encryptMode, subBlockLength, keyLength, initializationVectorBytes);

            //Encrypt session key, with public keys
            for (Receiver receiver : receiverList) {
                byte[] encryptedSesionKey = encryptSessionKey(receiver, secretKey);
                encryptFileHeader.addToUserList(new User(receiver.getName(), encryptedSesionKey));
            }

            String xml = createXmlHeader(encryptFileHeader);
            startNewTaskOfWriteDataToFile(cipher, xml);
        }
    }

    private SecretKey generateSessionKey(SecureRandom[] secureRandoms) {
        if (comboBoxLenghtKey.getValue() != null) {
            keyLength = comboBoxLenghtKey.getValue();
        } else {
            keyLength = "128";
        }

        SecretKey sessionKey = null;
        byte[] bytes = null;
        SecureRandom secureRandom = secureRandoms[0];

        long seedNumber = Runtime.getRuntime().freeMemory() ^ System.nanoTime() ^ System.currentTimeMillis();
        KeyGenerator keyGenerator = null;
        try {
            bytes = Long.toHexString(seedNumber).getBytes("UTF-8");
            secureRandom = new SecureRandom(bytes);
            keyGenerator = KeyGenerator.getInstance("Twofish", "BC");
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchProviderException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
        }

        keyGenerator.init(Integer.parseInt(keyLength), secureRandom);
        sessionKey = (SecretKey) keyGenerator.generateKey();
        secureRandoms[0] = secureRandom;

        return sessionKey;
    }

    private void readValueFromComboBox() {
        if (comboBoxEncryptMode.getValue() != null) {
            encryptMode = comboBoxEncryptMode.getValue();
        }
        if (comboBoxLenghtSubBlock.getValue() != null) {
            subBlockLength = comboBoxLenghtSubBlock.getValue();
        }
        if (comboBoxLenghtKey.getValue() != null) {
            keyLength = comboBoxLenghtKey.getValue();
        }
    }

    private String createCommandToEncrypt() {
        String command = "";
        if (encryptMode.equals("ECB") || encryptMode.equals("CBC")) {
            command = "Twofish/" + encryptMode + "/PKCS5Padding";
        } else if (encryptMode.equals("OFB") || encryptMode.equals("CFB")) {
            command = "Twofish/" + encryptMode + subBlockLength + "/PKCS5Padding";
        }
        return command;
    }

    private Cipher initializeCipherToEncrypt(String command, SecretKey secretKey,
            SecureRandom secureRandom) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(command, "BC");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, secureRandom);
        } catch (NoSuchAlgorithmException | NoSuchProviderException |
                NoSuchPaddingException | InvalidKeyException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
        }
        return cipher;
    }

    private byte[] setInitializationVector(Cipher cipher) {
        byte[] initializationVectorBytes = new byte[16];
        if (!encryptMode.equals("ECB")) {
            initializationVectorBytes = cipher.getIV();
        } else {
            initializationVectorBytes[0] = 0;
        }
        return initializationVectorBytes;
    }

    private byte[] encryptSessionKey(Receiver receiver, SecretKey sessionKey) {
        SecretKey secretKey = sessionKey;
        Cipher cipher;
        byte[] encryptedSesionKey = null;
        try {
            cipher = Cipher.getInstance("RSA");
            byte[] inputBytes = sessionKey.getEncoded();
            System.out.println("ALG: " + secretKey.getAlgorithm());
            System.out.println("FORMAT: " + secretKey.getFormat());
            cipher.init(Cipher.ENCRYPT_MODE, receiver.getPublicKey());
            encryptedSesionKey = cipher.doFinal(inputBytes);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
        }
        return encryptedSesionKey;
    }

    private String createXmlHeader(EncryptedFileHeader encryptFileHeader) {
        XStream xstream = new XStream();
        xstream.alias("EncryptedFileHeader", EncryptedFileHeader.class);
        xstream.alias("User", User.class);
        String xmlAdnotation = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
        String xml = xmlAdnotation + "\n" + xstream.toXML(encryptFileHeader) + "\n";
        return xml;
    }

    private void startNewTaskOfWriteDataToFile(Cipher cipher, String xml) {
        WriteData task = new WriteData(cipher, fileToEncryptInput, fileToEncryptOutput, xml);
        Thread thread = new Thread(task);
        progressBarEncryptMode.progressProperty().bind(task.progressProperty());
        thread.start();
    }

    @FXML
    void decryptModeChooseInputFile(ActionEvent event) {
        FileChooser chooseFileToDecrypt = new FileChooser();
        fileToDecryptInput = chooseFileToDecrypt.showOpenDialog(null);
        if (fileToDecryptInput != null) {
            textFiledChooseInputFileDecryptMode.setText(fileToDecryptInput.getPath());
            readHeaderOfFileToViewAvailableUsers();
        }
    }

    private void readHeaderOfFileToViewAvailableUsers() {
        byte[] fileInByteWithXmlHeaderAndCryptogram = readFileToDecrypt();

        String tmpString = new String(fileInByteWithXmlHeaderAndCryptogram);
        String[] tab = tmpString.split("</EncryptedFileHeader>\n");
        String xml = tab[0] + "</EncryptedFileHeader>\n";

        File tmpFile = createNewTemporaryFileWithOnlyCryptogram(
                fileInByteWithXmlHeaderAndCryptogram, xml);
        fileToDecryptInput = tmpFile;

        XStream xstream = new XStream();
        xstream.alias("EncryptedFileHeader", EncryptedFileHeader.class);
        xstream.alias("User", User.class);
        xml = xml.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "");
        encryptedFileHeader = (EncryptedFileHeader) xstream.fromXML(xml);
        //Add available users
        userList.removeAll(userList);
        userList.addAll(encryptedFileHeader.getUserList());
        receiverListViewDecryptMode.setItems(userList);
    }

    private byte[] readFileToDecrypt() {
        FileInputStream fis = null;
        byte[] file = null;
        try {
            fis = new FileInputStream(fileToDecryptInput);
            Path p = fileToDecryptInput.toPath();
            file = Files.readAllBytes(p);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                fis.close();
            } catch (IOException ex) {
                Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return file;
    }

    private File createNewTemporaryFileWithOnlyCryptogram(
            byte[] fileInByteWithXmlHeaderAndCryptogram, String xml) {
        File tmpFile = null;
        byte[] fileInByteWithOnlyCryptogram
                = new byte[fileInByteWithXmlHeaderAndCryptogram.length - xml.length()];
        for (int i = xml.length(); i < fileInByteWithXmlHeaderAndCryptogram.length; i++) {
            fileInByteWithOnlyCryptogram[i - xml.length()]
                    = fileInByteWithXmlHeaderAndCryptogram[i];
        }
        FileOutputStream fos = null;
        try {
            tmpFile = File.createTempFile(fileToDecryptInput.getName() + "temp", ".tmp");
            fos = new FileOutputStream(tmpFile);
            fos.write(fileInByteWithOnlyCryptogram);
        } catch (IOException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                fos.close();
                tmpFile.deleteOnExit();
            } catch (IOException ex) {
                Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return tmpFile;
    }

    @FXML
    void decryptModeChooseOutputFile(ActionEvent event) {
        FileChooser chooseOutputDecryptFilePath = new FileChooser();
        fileToDecryptOutput = chooseOutputDecryptFilePath.showSaveDialog(null);
        if (fileToDecryptOutput != null) {
            textFiledChooseOutputFileDecryptMode.setText(fileToDecryptOutput.getPath());
        }
    }

    @FXML
    void decryptFile(ActionEvent event) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
        if (fileToDecryptOutput != null && receiverListViewDecryptMode.getSelectionModel().getSelectedItem() != null) {
            User user = receiverListViewDecryptMode.getSelectionModel().getSelectedItem();
            this.password = passwordField.getText();

            PrivateKey rsaPrivateKey = decryptRSAPrivateKeyFromFile(user.getName());

            SecretKey sessionKey;
            if (rsaPrivateKey == null) {
                //New bad secret key. We decode file, but will be wrong!
                sessionKey = new SecretKeySpec("QQQQQQQQQQQQQQQQ".getBytes(), "Twofish");
            } else {
                sessionKey = decryptSessionKey(user, rsaPrivateKey);
            }

            String command = createCommandToDecrypt();
            Cipher cipher = initializeCipherToDecrypt(command, sessionKey);

            WriteData task = new WriteData(cipher, fileToDecryptInput, fileToDecryptOutput, null);
            Thread thread = new Thread(task);
            progressBarDecryptMode.progressProperty().bind(task.progressProperty());
            thread.start();
        }
    }

    //Zwraca odkodowany klucz prywatny
    private PrivateKey decryptRSAPrivateKeyFromFile(String name) {
        PrivateKey privateKey = null;
        File privateKeyFile = new File(usersPath + File.separator + name + ".priv");
        byte[] privateRSAKeyByte = null;
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(privateKeyFile);
            privateRSAKeyByte = new byte[(int) privateKeyFile.length()];
            fis.read(privateRSAKeyByte, 0, privateRSAKeyByte.length);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                fis.close();
            } catch (IOException ex) {
                Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        MessageDigest mD;
        Cipher cipher = null;
        try {
            mD = MessageDigest.getInstance("MD5");
            byte[] passMd5 = mD.digest(this.password.getBytes());
            SecretKey secretKey2Fish = new SecretKeySpec(passMd5, "DES");
            cipher = Cipher.getInstance("Twofish", "BC");
            cipher.init(Cipher.DECRYPT_MODE, secretKey2Fish);
            byte[] decryptPrivateKey = cipher.doFinal(privateRSAKeyByte);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decryptPrivateKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            privateKey = kf.generatePrivate(spec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException |
                InvalidKeyException | IllegalBlockSizeException | InvalidKeySpecException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            //Bad password = bad file, no sygnalize!
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
        }
        return privateKey;
    }

    private SecretKey decryptSessionKey(User user, PrivateKey rsaPrivateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        SecretKey sessionKey = null;
        byte[] sessionKeyByte = DatatypeConverter.parseBase64Binary(user.getSessionKey());
        Cipher cipher = null;
        byte[] decryptedSessionKey = null;
            //cipher = Cipher.getInstance("DSA", "BC");
            //cipher = Cipher.getInstance("Twofish","BC");
            cipher = Cipher.getInstance("RSA");
            //rsaPrivateKey.
            cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
            decryptedSessionKey = cipher.doFinal(sessionKeyByte);

        sessionKey = new SecretKeySpec(decryptedSessionKey, "Twofish");
        return sessionKey;
    }

    private String createCommandToDecrypt() {
        String command = "Twofish/" + encryptedFileHeader.getCipherMode();
        if (encryptedFileHeader.getCipherMode().equals("OFB") || encryptedFileHeader.getCipherMode().equals("CFB")) {
            command += encryptedFileHeader.getSegmentSize();
        }
        command += "/PKCS5Padding";
        return command;
    }

    private Cipher initializeCipherToDecrypt(String command, SecretKey sessionKey) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(command, "BC");
            IvParameterSpec iv = new IvParameterSpec(encryptedFileHeader.getIV());
            if (!encryptedFileHeader.getCipherMode().equals("ECB")) {
                cipher.init(Cipher.DECRYPT_MODE, sessionKey, iv);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, sessionKey);
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException |
                InvalidKeyException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
        }
        return cipher;
    }

}