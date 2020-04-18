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


public class Client {

    public static void main(String[] args) {

        String serverAddress = "localhost";

        int port = 4321;

        int numBytes = 0;

        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        try {

            System.out.println("Establishing connection to server...");

            // Connect to server and get the input and output streams
            clientSocket = new Socket(serverAddress, port);
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());

            System.out.println("Sending Certificate Request...");

            // Send certificate request to Server
            toServer.writeInt(0);

            while (true) {

                // Read the int transfer from server
                int packetType = fromServer.readInt();

                // If server is sending certificate name
                if (packetType == 0) {

                    System.out.println("Receiving certificate name...");

                    numBytes = fromServer.readInt();
                    byte[] certificatename = new byte[numBytes];
                    fromServer.readFully(certificatename, 0, numBytes);

                    fileOutputStream = new FileOutputStream("recv_" + new String(certificatename, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
                
                // If the server is sending the certificate file
                } else if ( packetType == 1) {

                    numBytes = fromServer.readInt();
                    byte[] block = new byte[numBytes];
                    fromServer.readFully(block, 0, numBytes);

                    if (numBytes > 0)
						bufferedFileOutputStream.write(block, 0, numBytes);

					if (numBytes < 117) {
                        System.out.println("Certificate Received Successfully!");
                        if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
                        break;
                    }

                }

            }

            System.out.println("Verifying the certificate");

            // Create X509Certificate object of CA
            InputStream fis = new FileInputStream("cacse.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert = (X509Certificate) cf.generateCertificate(fis);

            // Extract the public key of CA
            PublicKey ca_public = CAcert.getPublicKey();

            //Verify the certificate received using CA's public key
            verify(ca_public);

        } catch (Exception e) {e.printStackTrace();}
        
    }

    public static void verify( PublicKey key){

        try {
            // Create X509Certificate object of received certificate
            InputStream fis2 = new FileInputStream("recv_server-ca.crt");
            CertificateFactory cf2 = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert2 = (X509Certificate) cf2.generateCertificate(fis2);

            // Verify the certificate using public key given
            try {
                CAcert2.verify(key);
                System.out.println("Certificate verification pass");
            } catch (Exception e) {
                // Handle verification fail
                System.out.println("Certificate verification fail");
            }

        } catch (FileNotFoundException e) {
            // Handle certificate no found
            System.out.println("Can't find certificate");

        }

    }

}