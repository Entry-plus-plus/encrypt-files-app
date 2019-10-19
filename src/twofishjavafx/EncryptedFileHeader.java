package twofishjavafx;

import java.util.ArrayList;

public class EncryptedFileHeader {

    private String Algorithm;
    private String CipherMode;
    private String SegmentSize;
    private String KeySize;
    private byte[] IV;
    private ArrayList<User> ApprovedUsers;

    public EncryptedFileHeader() {
    }

    public EncryptedFileHeader(String Algorithm, String CipherMode, String SegmentSize,
            String KeySize, byte[] IV, ArrayList<User> ApprovedUsers) {
        this.Algorithm = Algorithm;
        this.CipherMode = CipherMode;
        this.SegmentSize = SegmentSize;
        this.KeySize = KeySize;
        this.IV = IV;
        this.ApprovedUsers = ApprovedUsers;
    }

    public EncryptedFileHeader(String Algorithm, String CipherMode,
            String SegmentSize, String KeySize, byte[] IV) {
        this.Algorithm = Algorithm;
        this.CipherMode = CipherMode;
        this.SegmentSize = SegmentSize;
        this.KeySize = KeySize;
        this.IV = IV;
        ApprovedUsers = new ArrayList<>();
    }

    public void addToUserList(User newUser) {
        ApprovedUsers.add(newUser);
    }

    public void delFromUserList(User userToDelete) {
        ApprovedUsers.remove(userToDelete);
    }

    public ArrayList<User> getUserList() {
        return ApprovedUsers;
    }

    public void setUserList(ArrayList<User> userList) {
        this.ApprovedUsers = userList;
    }

    public byte[] getIV() {
        return IV;
    }

    public void setIV(byte[] IV) {
        this.IV = IV;
    }

    public String getKeySize() {
        return KeySize;
    }

    public void setKeySize(String KeySize) {
        this.KeySize = KeySize;
    }

    public String getSegmentSize() {
        return SegmentSize;
    }

    public void setSegmentSize(String SegmentSize) {
        this.SegmentSize = SegmentSize;
    }

    public String getCipherMode() {
        return CipherMode;
    }

    public void setCipherMode(String CipherMode) {
        this.CipherMode = CipherMode;
    }

    public String getAlgorithm() {
        return Algorithm;
    }

    public void setAlgorithm(String Algorithm) {
        this.Algorithm = Algorithm;
    }

}
