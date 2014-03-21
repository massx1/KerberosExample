package net.tirasa.kerberosexample;

import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import sun.misc.BASE64Encoder;

public class FreeIPAThree extends Commons {

    public static void main(final String args[]) throws Throwable {
        setProperties();

        final String ticket = retrieveTicket();
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> MASSIMILIANO" + ticket);

        final DefaultHttpClient httpclient = createHttpClientForKerberosAuth();

        HttpParams params = new BasicHttpParams();
        HttpClientParams.setRedirecting(params, true);

//        byte[] encodedBytes = org.apache.commons.codec.binary.Base64.encodeBase64(ticket.getBytes());
//        String encoded = new String(encodedBytes);
        HttpPost post = createRequest();

//        post.addHeader("Authorization", "Negotiate " + encoded);
        post.setParams(params);

        try {
            printResponse(httpclient.execute(post));
        } finally {
            httpclient.getConnectionManager().shutdown();
        }

//        call(ticket);
    }

    private final static Oid KERB_V5_OID;

    private final static Oid KRB5_PRINCIPAL_NAME_OID;

    static {
        try {
            KERB_V5_OID = new Oid("1.2.840.113554.1.2.2");
            KRB5_PRINCIPAL_NAME_OID = new Oid("1.2.840.113554.1.2.2.1");

        } catch (final GSSException ex) {
            throw new Error(ex);
        }
    }

    public static String retrieveTicket() throws LoginException {

        //"TIRASA.NET", "olmo.tirasa.net", "HTTP/ebano.tirasa.net"
        final Subject subject = new Subject();
        final LoginContext lc = new LoginContext("un.security.jgss.login", subject);
        lc.login();

        // extract our principal
        final Set<Principal> principalSet = subject.getPrincipals();
        if (principalSet.size() != 1) {
            throw new AssertionError("No or several principals: " + principalSet);
        }
        final Principal userPrincipal = principalSet.iterator().next();

//        final TicketCreatorAction action = new TicketCreatorAction(userPrincipal.getName(), "HTTP/ebano.tirasa.net");
        final TicketCreatorAction action = new TicketCreatorAction(userPrincipal.getName(), "admin");
        final StringBuffer outputBuffer = new StringBuffer();
        action.setOutputBuffer(outputBuffer);
        Subject.doAsPrivileged(lc.getSubject(), action, null);

        return outputBuffer.toString();
    }

    private static class TicketCreatorAction implements PrivilegedAction {

        final String userPrincipal;

        final String applicationPrincipal;

        private StringBuffer outputBuffer;

        /**
         *
         * @param userPrincipal p.ex. <tt>MuelleHA@MYFIRM.COM</tt>
         * @param applicationPrincipal p.ex. <tt>HTTP/webserver.myfirm.com</tt>
         */
        private TicketCreatorAction(final String userPrincipal, final String applicationPrincipal) {
            this.userPrincipal = userPrincipal;
            this.applicationPrincipal = applicationPrincipal;
        }

        private void setOutputBuffer(final StringBuffer newOutputBuffer) {
            outputBuffer = newOutputBuffer;
        }

        /**
         * Only calls {@link #createTicket()}
         *
         * @return <tt>null</tt>
         */
        public Object run() {
            try {
                createTicket();
            } catch (final GSSException ex) {
                throw new Error(ex);
            }

            return null;
        }

        /**
         *
         * @throws GSSException
         */
        private void createTicket() throws GSSException {
            final GSSManager manager = GSSManager.getInstance();
            final GSSName clientName = manager.createName(userPrincipal, KRB5_PRINCIPAL_NAME_OID);
            final GSSCredential clientCred = manager.createCredential(clientName,
                    8 * 3600,
                    KERB_V5_OID,
                    GSSCredential.INITIATE_ONLY);

            final GSSName serverName = manager.createName(applicationPrincipal, KRB5_PRINCIPAL_NAME_OID);

            final GSSContext context = manager.createContext(serverName,
                    KERB_V5_OID,
                    clientCred,
                    GSSContext.DEFAULT_LIFETIME);
            context.requestMutualAuth(true);
            context.requestConf(false);
            context.requestInteg(true);

            final byte[] outToken = context.initSecContext(new byte[0], 0, 0);

            if (outputBuffer != null) {
                outputBuffer.append(String.format("Src Name: %s\n", context.getSrcName()));
                outputBuffer.append(String.format("Target  : %s\n", context.getTargName()));
                outputBuffer.append(new BASE64Encoder().encode(outToken));
                outputBuffer.append("\n");
            }

            context.dispose();
        }
    }

}
