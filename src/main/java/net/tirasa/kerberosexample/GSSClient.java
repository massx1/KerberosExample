package net.tirasa.kerberosexample;

import static net.tirasa.kerberosexample.Commons.LOG;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import sun.misc.BASE64Encoder;

public class GSSClient extends Commons {

    public static void main(final String args[]) throws LoginException, NoSuchAlgorithmException, KeyManagementException,
            IOException {
        setProperties();
        final String ticket = retrieveTicket("HTTP/olmo.tirasa.net");
        LOG.debug("Calling server with ticket {}", ticket);
        postWithTicket(ticket);
    }

    public static String retrieveTicket(final String applicationPrincipal) throws LoginException {
        final Subject subject = login();

        LOG.debug("Authenticated with {}", subject);

        final Set<Principal> principalSet = subject.getPrincipals();
        if (principalSet.size() != 1) {
            LOG.error("No or several principals {}", principalSet);
            throw new AssertionError("No or several principals: " + principalSet);
        }
        final Principal userPrincipal = principalSet.iterator().next();
        LOG.debug("user principale found {}", userPrincipal);

        final TicketCreatorAction action = new TicketCreatorAction(userPrincipal.getName(), applicationPrincipal);
        final StringBuffer outputBuffer = new StringBuffer();
        action.setOutputBuffer(outputBuffer);
        Subject.doAsPrivileged(subject, action, null);

        return outputBuffer.toString();
    }

    private static class TicketCreatorAction implements PrivilegedAction {

        private final String userPrincipal;

        private final String applicationPrincipal;

        private StringBuffer outputBuffer;

        public TicketCreatorAction(final String userPrincipal, final String applicationPrincipal) {
            this.userPrincipal = userPrincipal;
            this.applicationPrincipal = applicationPrincipal;
        }

        public void setOutputBuffer(final StringBuffer newOutputBuffer) {
            outputBuffer = newOutputBuffer;
        }

        @Override
        public Object run() {
            try {
                LOG.debug("Creating ticket");
                createTicket();
            } catch (final GSSException ex) {
                LOG.error("GSSException", ex);
                throw new Error(ex);
            }
            return null;
        }

        private void createTicket() throws GSSException {
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

            final byte[] outToken = context.initSecContext(new byte[0], 0, 0);

            LOG.debug("Token created {}", outToken);

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
