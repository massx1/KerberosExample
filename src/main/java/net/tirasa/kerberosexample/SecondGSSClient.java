package net.tirasa.kerberosexample;

import static net.tirasa.kerberosexample.Commons.KERB_V5_OID;
import static net.tirasa.kerberosexample.Commons.KRB5_PRINCIPAL_NAME_OID;
import static net.tirasa.kerberosexample.Commons.LOG;
import static net.tirasa.kerberosexample.Commons.setProperties;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.Socket;
import java.security.AccessController;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;
import sun.misc.BASE64Encoder;

public class SecondGSSClient extends Commons {

    public static void main(final String args[]) throws LoginException, NoSuchAlgorithmException, KeyManagementException,
            IOException, PrivilegedActionException {
        setProperties();
        final String ticket = retrieveTicket(SERVICE_PRINCIPAL_NAME);
        LOG.debug("Calling server with ticket {}", ticket);
        postWithTicket(ticket);
    }

    public static String retrieveTicket(final String applicationPrincipal) throws LoginException,
            PrivilegedActionException, MalformedURLException {
//        final Subject subject = login();
        final Subject subject = kerberosLogin();

        LOG.debug("Authenticated with {}", subject);

        final Set<Principal> principalSet = subject.getPrincipals();
        if (principalSet.size() != 1) {
            LOG.error("No or several principals {}", principalSet);
            throw new AssertionError("No or several principals: " + principalSet);
        }
        final Principal userPrincipal = principalSet.iterator().next();
        LOG.debug("user principale found {}", userPrincipal);

        final GssClientAction action = new SecondGSSClient.GssClientAction(userPrincipal.getName(),
                applicationPrincipal, "olmo.tirasa.net", 88);

        Subject.doAs(subject, action);
        return "";
    }

    static class GssClientAction implements PrivilegedExceptionAction {

        private String userPrincipal;

        private String applicationPrincipal;

        private String hostName;

        private int port;

        GssClientAction(String userPrincipal, String applicationPrincipal, String hostName, int port) {
            this.userPrincipal = userPrincipal;
            this.applicationPrincipal = applicationPrincipal;
            this.hostName = hostName;
            this.port = port;
        }

        public Object run() throws Exception {
            Socket socket = new Socket(hostName, port);
            DataInputStream inStream = new DataInputStream(socket.getInputStream());
            DataOutputStream outStream = new DataOutputStream(socket.getOutputStream());

            System.out.println("Connected to address " + socket.getInetAddress());

            /*
             * This Oid is used to represent the Kerberos version 5 GSS-API
             * mechanism. It is defined in RFC 1964. We will use this Oid
             * whenever we need to indicate to the GSS-API that it must
             * use Kerberos for some purpose.
             */
            final GSSManager manager = GSSManager.getInstance();
            final GSSName clientName = manager.createName(userPrincipal, KRB5_PRINCIPAL_NAME_OID);

            LOG.debug("GSSname client name created {}", clientName);

            final GSSCredential clientCred = manager.createCredential(clientName,
                    8 * 3600,
                    KERB_V5_OID,
                    GSSCredential.INITIATE_ONLY);

            LOG.debug("GSSCredentials created {}", clientCred);

            final GSSName serverName = manager.createName(applicationPrincipal, KRB5_PRINCIPAL_NAME_OID);

            LOG.debug("GSSName server name created {}", serverName);

            final GSSContext context = manager.createContext(serverName,
                    KERB_V5_OID,
                    clientCred,
                    GSSContext.DEFAULT_LIFETIME);

            LOG.debug("GSSContext created {}", context);

            context.requestMutualAuth(true);
            context.requestConf(false);
            context.requestInteg(true);

            // Set the desired optional features on the context. The client
            // chooses these options.
            context.requestMutualAuth(true);  // Mutual authentication
            context.requestConf(true);  // Will use confidentiality later
            context.requestInteg(true); // Will use integrity later

            // Do the context eastablishment loop
            byte[] token = new byte[0];

            while (!context.isEstablished()) {

                // token is ignored on the first call
                token = context.initSecContext(token, 0, token.length);

                // Send a token to the server if one was generated by
                // initSecContext
                if (token != null) {

                    outStream.writeInt(token.length);
                    outStream.write(token);
                    outStream.flush();
                }

                // If the client is done with context establishment
                // then there will be no more tokens to read in this loop
                if (!context.isEstablished()) {
                    token = new byte[inStream.readInt()];
                    inStream.readFully(token);
                }
            }

            System.out.println("Context Established! ");
            System.out.println("Client principal is " + context.getSrcName());
            System.out.println("Server principal is " + context.getTargName());

            /*
             * If mutual authentication did not take place, then only the
             * client was authenticated to the server. Otherwise, both
             * client and server were authenticated to each other.
             */
            if (context.getMutualAuthState()) {
                System.out.println("Mutual authentication took place!");
            }

            byte[] messageBytes = "Hello There!".getBytes("UTF-8");

            /*
             * The first MessageProp argument is 0 to request
             * the default Quality-of-Protection.
             * The second argument is true to request
             * privacy (encryption of the message).
             */
            MessageProp prop = new MessageProp(0, true);

            /*
             * Encrypt the data and send it across. Integrity protection
             * is always applied, irrespective of confidentiality
             * (i.e., encryption).
             * You can use the same token (byte array) as that used when
             * establishing the context.
             */
            System.out.println("Sending message: " + new String(messageBytes, "UTF-8"));
            token = context.wrap(messageBytes, 0, messageBytes.length, prop);
            outStream.writeInt(token.length);
            outStream.write(token);
            outStream.flush();

            /*
             * Now we will allow the server to decrypt the message,
             * append a time/date on it, and send then it back.
             */
            token = new byte[inStream.readInt()];
            System.out.println("Will read token of size " + token.length);
            inStream.readFully(token);
            byte[] replyBytes = context.unwrap(token, 0, token.length, prop);

            System.out.println("Received message: " + new String(replyBytes, "UTF-8"));

            System.out.println("Done.");
            context.dispose();
            socket.close();

            return null;
        }
    }

    private static final String getHexBytes(byte[] bytes, int pos, int len) {

        StringBuffer sb = new StringBuffer();
        for (int i = pos; i < (pos + len); i++) {

            int b1 = (bytes[i] >> 4) & 0x0f;
            int b2 = bytes[i] & 0x0f;

            sb.append(Integer.toHexString(b1));
            sb.append(Integer.toHexString(b2));
            sb.append(' ');
        }
        return sb.toString();
    }

    private static final String getHexBytes(byte[] bytes) {
        return getHexBytes(bytes, 0, bytes.length);
    }
}
