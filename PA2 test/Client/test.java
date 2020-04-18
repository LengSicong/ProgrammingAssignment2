import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class test {
    public static void main(String[] args) {
        InputStream fis2 = new FileInputStream("server-ca.crt");
        CertificateFactory cf2 = CertificateFactory.getInstance("X.509");
        X509Certificate CAcert2 = (X509Certificate) cf2.generateCertificate(fis2);
    }
}