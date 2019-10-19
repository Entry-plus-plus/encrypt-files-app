package twofishjavafx;

import java.security.PublicKey;

public class Receiver {

    private String Name;

    private PublicKey PublicKey;

    public Receiver(String Name, PublicKey PublicKey) {
        this.Name = Name;
        this.PublicKey = PublicKey;
    }

    public PublicKey getPublicKey() {
        return PublicKey;
    }

    public void setPublicKey(PublicKey PublicKey) {
        this.PublicKey = PublicKey;
    }

    public String getName() {
        return Name;
    }

    public void setName(String name) {
        this.Name = name;
    }

    @Override
    public String toString() {
        return Name;
    }
}
