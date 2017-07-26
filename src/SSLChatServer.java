import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.util.logging.Logger;

public class SSLChatServer {
    private static final String KEYSTORE_PATH = "C:\\Users\\admin\\IdeaProjects\\HTTPSServer\\test.jks";
    private final int SERVER_PORT = 2626;
    private boolean isServerDone = false;
    private static Logger logger = Logger.getGlobal();

    public static void main(String[] args) {
        SSLChatServer server = new SSLChatServer();
        server.run();
    }

    //create and init the SSLContext
    private SSLContext createSSLContext() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            char[] password = "passphrase".toCharArray();
            keyStore.load(new FileInputStream(KEYSTORE_PATH), password);

            //create key manager
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keyStore, password);
            KeyManager[] km = kmf.getKeyManagers();

            //create trust manager
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(keyStore);
            TrustManager[] tm = tmf.getTrustManagers();

            //init SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLSv1");
            sslContext.init(km, tm, null);
            return sslContext;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    //run the server
    public void run() {
        SSLContext sslContext = createSSLContext();

        try {
            //create SSLServerSocketFactory
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

            //create server socket
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(SERVER_PORT);

            logger.info("SSL server started");
            while (!isServerDone) {
                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();

                //start the server thread
                new ServerThread(sslSocket).start();
                logger.info("Server thread started.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //thread handling the socket from client
    static class ServerThread extends Thread {
        private SSLSocket sslSocket = null;

        public ServerThread(SSLSocket sslSocket) {
            this.sslSocket = sslSocket;
        }

        @Override
        public void run() {
            sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());

            try {
                //start handshake
                sslSocket.startHandshake();

                //get session after the connection is established
                SSLSession sslSession = sslSocket.getSession();
                System.out.println("SSLSession:");
                System.out.println("Protocol: " + sslSession.getProtocol());
                System.out.println("Cipher suite: " + sslSession.getCipherSuite());

                new Thread(new InputStreamListener(sslSocket)).start();


                DataOutputStream dataOutputStream = new DataOutputStream(sslSocket.getOutputStream());
                BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
                while (!sslSocket.isClosed()) {
                    System.out.println("Server>>");
                    String serverMessage = br.readLine();
                    dataOutputStream.writeUTF(serverMessage);
                    dataOutputStream.flush();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }


        private class InputStreamListener implements Runnable {

            private final SSLSocket sslSocket;

            public InputStreamListener(SSLSocket sslSocket) {
                this.sslSocket = sslSocket;
            }

            @Override
            public void run() {
                DataInputStream dataInputStream = null;
                try {
                    dataInputStream = new DataInputStream(sslSocket.getInputStream());
                    while (!sslSocket.isClosed()) {
                        System.out.println("Client>>" + dataInputStream.readUTF());
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    try {
                        dataInputStream.close();
                        sslSocket.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

}
