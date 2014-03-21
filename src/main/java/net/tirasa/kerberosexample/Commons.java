package net.tirasa.kerberosexample;

import com.sun.security.auth.module.Krb5LoginModule;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.ws.rs.core.MediaType;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.ParseException;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.ws.security.util.Base64;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;
import org.slf4j.LoggerFactory;

public abstract class Commons {

    protected static final org.slf4j.Logger LOG = LoggerFactory.getLogger(Commons.class);

    protected static final String SERVICE_PRINCIPAL_NAME = "ldap/olmo.tirasa.net";

    protected final static Oid KERB_V5_OID;

    protected final static Oid KRB5_PRINCIPAL_NAME_OID;

    static {
        try {
            KERB_V5_OID = new Oid("1.2.840.113554.1.2.2");
            KRB5_PRINCIPAL_NAME_OID = new Oid("1.2.840.113554.1.2.2.1");

        } catch (final GSSException ex) {
            throw new Error(ex);
        }
    }

    protected final static String JAAS_CONF = "un.security.jgss.login";

    protected final static String KEYTAB_FILENAME = "/var/tmp/ebano.keytab";

    protected static DefaultHttpClient createHttpClientForKerberosAuth() throws
            NoSuchAlgorithmException,
            KeyManagementException,
            KeyStoreException,
            UnrecoverableKeyException {
        final TrustStrategy acceptingTrustStrategy = new TrustStrategy() {

            @Override
            public boolean isTrusted(final X509Certificate[] certificate, String authType) {
                return true;
            }
        };
        final SSLSocketFactory sf = new SSLSocketFactory(acceptingTrustStrategy,
                SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
        final SchemeRegistry registry = new SchemeRegistry();
        registry.register(new Scheme("https", 443, sf));
        final ClientConnectionManager ccm = new PoolingClientConnectionManager(registry);

        final DefaultHttpClient httpclient = new DefaultHttpClient(ccm);

        final Credentials use_jaas_creds = new Credentials() {

            @Override
            public String getPassword() {
                return null;
            }

            @Override
            public Principal getUserPrincipal() {
                return null;
            }

        };
        httpclient.getCredentialsProvider().setCredentials(new AuthScope(null, -1, null), use_jaas_creds);

        return httpclient;
    }

    protected static HttpPost createRequest() throws UnsupportedEncodingException {
        final HttpPost request = new HttpPost("https://olmo.tirasa.net/ipa/json");
        LOG.debug("Creating requet to {}", request.getURI());
        final List<NameValuePair> params = new ArrayList<NameValuePair>(2);
        params.add(new BasicNameValuePair("method", "user_find"));
        params.add(new BasicNameValuePair("params", "all"));
        request.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));

        request.addHeader("referer", "https://olmo.tirasa.net/ipa");
        request.addHeader("Content-Type", MediaType.APPLICATION_JSON);
        request.addHeader("Accept", MediaType.APPLICATION_JSON);
        return request;
    }

    protected static void printResponse(final HttpResponse response) throws ParseException, IOException {
        final HttpEntity entity = response.getEntity();

        LOG.debug("Response status {}", response.getStatusLine());

        if (entity != null) {
            LOG.debug("response \n {}", EntityUtils.toString(entity));
        }
        EntityUtils.consume(entity);
    }

    protected static void setProperties() {
        System.setProperty("java.security.auth.login.config", "/var/tmp/jass.conf");
        System.setProperty("sun.security.krb5.debug", "true");
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
        System.setProperty("target.service.principal.name", "ldap/olmo.tirasa.net");
        System.setProperty("java.security.krb5.realm", "TIRASA.NET");
        System.setProperty("java.security.krb5.kdc", "olmo.tirasa.net");
        LOG.debug("Properties set ok");
    }

    protected static void postWithTicket(final String ticket) throws
            NoSuchAlgorithmException,
            KeyManagementException {
        final TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {

            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }
        };

        final SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        final HostnameVerifier allHostsValid = new HostnameVerifier() {

            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };

        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

        try {
            final URL url = new URL("https://olmo.tirasa.net/ipa/json");

            LOG.debug("URL set to {}", url);

            final URLConnection con = url.openConnection();
            con.setRequestProperty("Authorization", "Negotiate: " + Base64.encode(ticket.getBytes()));
            final Reader reader = new InputStreamReader(con.getInputStream());

            while (true) {
                int ch = reader.read();
                if (ch == -1) {
                    break;
                }
                LOG.debug("RETURN STATUS {}", (char) ch);
            }
        } catch (IOException ioe) {
            LOG.error("IOE ", ioe);
        }
    }

    protected static void testLogin() throws LoginException {
        LoginContext lc = new LoginContext(JAAS_CONF);
        lc.login();
        Subject serviceSubject = lc.getSubject();
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>> " + serviceSubject.toString());
    }

    protected static Subject login() throws LoginException, MalformedURLException {
        LOG.debug("Trying login with {} configuration in {} keytab file", JAAS_CONF, KEYTAB_FILENAME);
        LoginContext lc = new LoginContext(JAAS_CONF);
        lc.login();
        return lc.getSubject();
    }

    protected static Subject kerberosLogin() throws LoginException, MalformedURLException {
        LOG.debug("Trying login with {} configuration in {} keytab file", JAAS_CONF, KEYTAB_FILENAME);

        Subject subject = login();
        final Krb5LoginModule krb5 = new Krb5LoginModule();

        Map<String, String> map = new HashMap<String, String>();
        map.put("client", "true");
        map.put("refreshKrb5Config", "true");
        map.put("useKeyTab", "true");
        map.put("debug", "true");
        map.put("keyTab", "/var/tmp/ebano.keytab");
        map.put("principal", "HTTP/ebano.tirasa.net");

        krb5.initialize(subject, null, null, map);
        krb5.login();
        krb5.commit();

        return subject;
    }
}
