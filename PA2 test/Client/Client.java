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
import java.security.spec.ECField;
import java.util.Arrays;
import java.util.Scanner;
import java.security.SecureRandom;
import javax.crypto.*;


public class Client {

    public static void main(String[] args) {

        String serverAddress = "localhost";

        String uploadfilename = null;

        Boolean whetherInput = false;

        int port = 4321;

        int numBytes = 0;

        byte[] identity;

        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        try {

            System.out.println("Establishing connection to server...");

            // Connect to server and get the input and output streams
            clientSocket = new Socket(serverAddress, port);
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());

            System.out.println("Sending Identity Request...");

            // Send identity request to Server
            toServer.writeInt(0);

            // Send nonce to the server
            String nonce = nonceGenerator();
            toServer.writeInt(nonce.getBytes().length);
            toServer.write(nonce.getBytes());

            // while loop for waiting identity message from server
            while (true) {
                
                //Read the int transfer from the server
                int packetType2 = fromServer.readInt();

                // If server is sending encrypted identity message and nonce
                if (packetType2 == 0){

                    System.out.println("Receiving encrypted greeting and nonce message...");

                    numBytes = fromServer.readInt();
                    identity = new byte[numBytes];
                    fromServer.readFully(identity, 0, numBytes);

                    System.out.println("Encrypted Greeting and nonce message received");
                    //String identity_String = new String(identity);

                    // Identity checking finished
                    break;
                }

            }
            
            System.out.println("Sending Certificate Request...");

            // Send certificate request to Server
            toServer.writeInt(1);
            
            // while loop for certificate verification
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

                    System.out.println("Receiving certificate file...");

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

            // Create X509Certificate object of CA
            InputStream fis3 = new FileInputStream("recv_server-ca.crt");
            CertificateFactory cf3 = CertificateFactory.getInstance("X.509");
            X509Certificate serverCert = (X509Certificate) cf3.generateCertificate(fis3);

            // Extract the public key of server
            PublicKey server_public = serverCert.getPublicKey();

            System.out.println("Server public key extracted");

            // Use public key to decrypt the encrypted-nonce
            Cipher clientCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            clientCipher.init(Cipher.DECRYPT_MODE, server_public);

            byte[] decryptedGreeting = clientCipher.doFinal(identity);
            String greetingNonce = new String(decryptedGreeting);

            //System.out.println(greetingNonce);
            //System.out.println("Hello, this is SecStore! Please verify this nonce: " + nonce);
            //System.out.println(nonce);
            
            // Verify the nonce
            if (greetingNonce.equals("Hello, this is SecStore! Please verify this nonce: " + nonce)){
                System.out.println("Authentification pass!");
            }else{
                System.err.println("Authentification fail!");
                System.out.println("ByeBye~");
                toServer.close();
                fromServer.close();
                clientSocket.close();
            }


            // Generate the symmetric session key for further uploading
            KeyGenerator sym_keyGen = KeyGenerator.getInstance("AES");
            sym_keyGen.init(128); 
            SecretKey sym_key = sym_keyGen.generateKey();

            // Encrypt the symmetric session key using server's public key
            Cipher sym_cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            sym_cipher.init(Cipher.ENCRYPT_MODE, server_public);
            byte[] encrypted_symkey = sym_cipher.doFinal(sym_key.getEncoded());

            System.out.println("Sending symmtric session key to server...");

            // Send the symmtric session key to server
            toServer.writeInt(2);
            toServer.writeInt(encrypted_symkey.length);
            toServer.write(encrypted_symkey);

            System.out.println("Symmtric session key sended");

            // Loop for user input and upload files
            while (true){

                // User input for the filename of upload file
                Scanner myScanner = new Scanner(System.in);
                System.out.println("Enter the name of file you want to upload: ");

                while( !whetherInput ){
                    if (myScanner.hasNextLine()){
                    whetherInput = true;
                    uploadfilename = myScanner.nextLine();
                    }
                }
                //myScanner.close();

                if (uploadfilename.equals("quit")){
                    // Send connection close signal to server
                    toServer.writeInt(4);
                    clientSocket.close();
                    toServer.close();
                    fromServer.close();
                    break;
                }

                // Send the encrypted filename 
                toServer.writeInt(3);

                // Encrypted the filename using symmetric session key
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); 
                cipher.init(Cipher.ENCRYPT_MODE, sym_key);

                byte[] encryptedfilename = cipher.doFinal(uploadfilename.getBytes());

                // send the filename
                toServer.writeInt(0);
                toServer.writeInt(encryptedfilename.length);
                toServer.write(encryptedfilename);

                // Open the file
                try {
                    fileInputStream = new FileInputStream(uploadfilename);
                    bufferedFileInputStream = new BufferedInputStream(fileInputStream);

                    byte[] fromFileBuffer = new byte[128];
                    // Send the file
                    for (boolean fileEnded = false; !fileEnded;) {
                        
                        // Encrypt the file
                        numBytes = bufferedFileInputStream.read(fromFileBuffer);
                        byte[] fromFileBuffer2 = Arrays.copyOfRange(fromFileBuffer, 0, numBytes);
                        byte[] encryptedFileBuffer = cipher.doFinal(fromFileBuffer2);
                        
                        fileEnded = numBytes < 128;

                        toServer.writeInt(1);
                        toServer.writeInt(encryptedFileBuffer.length);
                        toServer.writeInt(numBytes);
                        toServer.write(encryptedFileBuffer);
                        toServer.flush();
                    }

                    bufferedFileInputStream.close();
                    fileInputStream.close();

                    System.out.println("The file has successfully uploaded to the server");
                    
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("Something wrong with the file name you type in");
                }

                whetherInput = false;
                

            } 




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

        } catch (Exception e) {
            // Handle certificate no found
            System.out.println("Can't find certificate");

        }

    }

    public static String nonceGenerator(){
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder stringBuilder = new StringBuilder();
        for (int i=0; i<15; i++){
            stringBuilder.append(secureRandom.nextInt(10));
        }
        String randomNumber = stringBuilder.toString();
        return randomNumber;
    }

}