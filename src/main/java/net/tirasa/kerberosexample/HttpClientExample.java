package net.tirasa.kerberosexample;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import javax.security.auth.login.LoginException;
import org.apache.http.impl.client.DefaultHttpClient;

public class HttpClientExample extends Commons {

    public static void main(final String[] args) throws IOException, NoSuchAlgorithmException, KeyManagementException,
            LoginException, KeyStoreException, UnrecoverableKeyException {
        setProperties();
        final DefaultHttpClient httpclient = createHttpClientForKerberosAuth();
        LOG.debug("Client kerberos created");

        try {
            printResponse(httpclient.execute(createRequest()));
        } finally {
            httpclient.getConnectionManager().shutdown();
        }
    }
}
