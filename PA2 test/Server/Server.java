import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
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
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Server {

    public static void main(String[] args) {

        int port = 4321;

        int numBytes = 0;

        String certificateName = "server-ca.crt";

        PrivateKey server_privateKey = null;
        SecretKey sym_key = null;

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        try {
            welcomeSocket = new ServerSocket(port);
        } catch (Exception e) {
            e.printStackTrace();
        }

        while (true) {
            try {

                connectionSocket = welcomeSocket.accept();
                fromClient = new DataInputStream(connectionSocket.getInputStream());
                toClient = new DataOutputStream(connectionSocket.getOutputStream());

                while (!connectionSocket.isClosed()) {

                    // Read the int transfer from the client
                    int packetType = fromClient.readInt();

                    // If the client is request for certificate
                    if (packetType == 1) {

                        System.out.println("Received certificate request from client");

                        System.out.println("Sending certificate name to client...");

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
                        for (boolean fileEnded = false; !fileEnded;) {
                            numBytes = bufferedFileInputStream.read(fromFileBuffer);
                            fileEnded = numBytes < 117;

                            toClient.writeInt(1);
                            toClient.writeInt(numBytes);
                            toClient.write(fromFileBuffer);
                            toClient.flush();
                        }

                        bufferedFileInputStream.close();
                        fileInputStream.close();

                        System.out.println("Certificate successfully sended");
                        // fromClient.close();
                        // toClient.close();
                        // connectionSocket.close();

                        // If the client is request for identity message
                    } else if (packetType == 0) {

                        System.out.println("Received identity request and nonce from client");

                        // Receiving the nonce from client
                        numBytes = fromClient.readInt();
                        byte[] nonce = new byte[numBytes];
                        fromClient.readFully(nonce, 0, numBytes);
                        String non_String = new String(nonce);

                        // Encrpt the greeting message + nonce using server's private key
                        String greetingMessage = "Hello, this is SecStore! Please verify this nonce: " + non_String;

                        System.out.println("greeting message and nonce sended: " + greetingMessage);

                        Cipher serverCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        server_privateKey = privateKeyGet("server_private_key.der");
                        serverCipher.init(Cipher.ENCRYPT_MODE, server_privateKey);

                        byte[] greetingNonce = serverCipher.doFinal(greetingMessage.getBytes());

                        System.out.println("Sending encrypted greeting message and nonce to client...");

                        // Send encrypted greeting message and nonce to client
                        toClient.writeInt(0);
                        toClient.writeInt(greetingNonce.length);
                        toClient.write(greetingNonce);

                        // If the client is sending symmtric session key request to server
                    } else if (packetType == 2) {

                        // Reiceve encrypted and encoded symmetric session key from client
                        numBytes = fromClient.readInt();
                        byte[] encryptedSessionKey = new byte[numBytes];
                        fromClient.readFully(encryptedSessionKey, 0, numBytes);

                        // Decrypt the key
                        Cipher serverCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        server_privateKey = privateKeyGet("server_private_key.der");
                        serverCipher.init(Cipher.DECRYPT_MODE, server_privateKey);

                        byte[] decrypted_symkey = serverCipher.doFinal(encryptedSessionKey);

                        // convert key from byte[] to Key
                        sym_key = new SecretKeySpec(decrypted_symkey, 0, decrypted_symkey.length, "AES");

                        System.out.println("Received symmtric session key from client");

                        // Client is uploading files to server
                    } else if (packetType == 3) {

                        while (true) {

                            int packetType2 = fromClient.readInt();

                            // If the packet is for transferring the name
                            if (packetType2 == 0) {

                                System.out.println("Receiving file...");

                                numBytes = fromClient.readInt();
                                byte[] encryptedFileName = new byte[numBytes];
                                fromClient.readFully(encryptedFileName, 0, numBytes);

                                // Decrypt the filename using the symmetric session key
                                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                                cipher.init(Cipher.DECRYPT_MODE, sym_key);

                                byte[] decryptedfilename = cipher.doFinal(encryptedFileName);

                                fileOutputStream = new FileOutputStream(
                                        new String(decryptedfilename, 0, decryptedfilename.length));
                                bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                                System.out.println("Filename:"
                                        + new String(decryptedfilename, 0, decryptedfilename.length) + " received");

                                // If the packet is for transferring a chunk of the file
                            } else if (packetType2 == 1) {

                                // System.out.println("Receiving files...");

                                numBytes = fromClient.readInt();
                                Integer end = fromClient.readInt();
                                byte[] encryptedBlock = new byte[numBytes];
                                fromClient.readFully(encryptedBlock, 0, numBytes);

                                // Decrypt the files
                                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                                cipher.init(Cipher.DECRYPT_MODE, sym_key);

                                byte[] decryptedBlock = cipher.doFinal(encryptedBlock);

                                // Print the received encrypted file chunk
                                // System.out.println(new String(encryptedBlock));

                                // Print the unencrypted file chunk
                                // System.out.println(new String(decryptedBlock));

                                if (end > 0)
                                    bufferedFileOutputStream.write(decryptedBlock, 0, decryptedBlock.length);

                                if (end < 128) {
                                    System.out.println("File received successfully");

                                    if (bufferedFileOutputStream != null)
                                        bufferedFileOutputStream.close();
                                    if (bufferedFileOutputStream != null)
                                        fileOutputStream.close();

                                    // End this file transfer
                                    break;
                                }

                            }

                        }

                        // Closing the socket
                    } else if (packetType == 4) {
                        connectionSocket.close();
                        toClient.close();
                        fromClient.close();
                        System.out.println("Current connection Lost");
                        System.out.println("Waitting for the next client...");
                    }

                }

            } catch (Exception e) {
                e.printStackTrace();
            }

        }

    }

    public static PrivateKey privateKeyGet(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

}
