
package twofishjavafx;

import javax.xml.bind.DatatypeConverter;

public class User {

    private String Name;

    private String SessionKey;

    public String getSessionKey() {
        return SessionKey;
    }

    public User(String Name, byte[] SessionKey) {
        this.Name = Name;
        this.SessionKey = DatatypeConverter.printBase64Binary(SessionKey);
    }

    public void setSessionKey(String SessionKey) {
        this.SessionKey = SessionKey;
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
