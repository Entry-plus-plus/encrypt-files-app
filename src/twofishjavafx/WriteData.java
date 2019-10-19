
package twofishjavafx;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.concurrent.Task;
import javax.crypto.Cipher;

public class WriteData extends Task {
    FileOutputStream fos;
    FileInputStream fis;
    byte[] textByte1;
    byte[] textByte2;
    Cipher cipher;
    File fileInput;
    File fileOutput;

    public WriteData(Cipher cipher, File fileInput, File fileOutput, String toWrite) {
        this.textByte1 = new byte[128];
        this.textByte2 = new byte[128];
        this.cipher = cipher;
        this.fileInput = fileInput;
        this.fileOutput = fileOutput;
        try {
            this.fos = new FileOutputStream(fileOutput);
            this.fis = new FileInputStream(fileInput);
            if (toWrite != null) {
                fos.write(toWrite.getBytes());
            }
        } catch (FileNotFoundException ex) {
            Logger.getLogger(WriteData.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(WriteData.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    protected Object call() throws Exception {
        int readedByte;
        long i = 0;
        byte val = 0;
        try {
            while ((readedByte = fis.read(textByte1)) != -1) { // -1 = End of file               
                if (readedByte == 128 && this.fileInput.length() != 128 
                        && this.fileInput.length() - i != 128) {
                    textByte2 = cipher.update(textByte1);                    
                    i += 128;
                }
                else 
                {
                    textByte1 = deleteByteNull(textByte1);
                    textByte2 = cipher.doFinal(textByte1);                    
                    i += readedByte;
                }
                fos.write(textByte2);
                updateProgress(i, fileInput.length());
                this.textByte1 = new byte[128];
                this.textByte2 = new byte[128];
                Arrays.fill(textByte1, val);
                Arrays.fill(textByte2, val);
            }
        } catch (IOException ex) {
            Logger.getLogger(WriteData.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            fos.close();
            fis.close();
            updateProgress(fileInput.length(), fileInput.length());
        }

        return true;
    }

    private byte[] deleteByteNull(byte[] input) {
        int i;
        for (i = input.length - 1; i >= 0; i--) {
            if (input[i] != 0) {
                break;
            }
        }
        return Arrays.copyOfRange(input, 0, ++i);
    }
}
