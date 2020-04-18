import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class Server {

    public static void main(String[] args) {

        int port = 4321;

        int numBytes = 0;

        String certificateName = "server-ca.crt";

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        try{
            welcomeSocket = new ServerSocket(port);
            connectionSocket = welcomeSocket.accept();
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());

            while (!connectionSocket.isClosed()){

                // Read the int transfer from the client
                int packetType = fromClient.readInt();

                // If the client is request for certificate
                if (packetType == 0) {

                    System.out.println("Received certificate request from client");

                    System.out.println("Sending certificate name to server...");

                    // Send the certificate name
                    toClient.writeInt(0);
                    toClient.writeInt(certificateName.getBytes().length);
                    toClient.write(certificateName.getBytes());

                    // Open the certificate file
                    fileInputStream = new FileInputStream(certificateName);
                    bufferedFileInputStream = new BufferedInputStream(fileInputStream);

                    byte[] fromFileBuffer = new byte[117];

                    System.out.println("Sending certificate to client...");

                    // Send the certificate to the client
                    for (boolean fileEnded= false; !fileEnded;){
                        numBytes = bufferedFileInputStream.read(fromFileBuffer);
                        fileEnded = numBytes < 117;

                        toClient.writeInt(1);
                        toClient.writeInt(numBytes);
                        toClient.write(fromFileBuffer);
                        toClient.flush();

                    }

                    System.out.println("Certificate successfully sended");
                    fromClient.close();
                    toClient.close();
                    connectionSocket.close();
                    

                    
                }

            }

        } catch (Exception e) {e.printStackTrace();}



    }

    public static PrivateKey get(String filename) throws Exception{
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

}
