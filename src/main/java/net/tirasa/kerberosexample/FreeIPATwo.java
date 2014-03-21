package net.tirasa.kerberosexample;

import static org.apache.cxf.transport.http.auth.HttpAuthHeader.AUTH_TYPE_NEGOTIATE;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.ws.rs.core.Response;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.interceptor.LoggingOutInterceptor;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.jaxrs.security.KerberosAuthOutInterceptor;
import org.apache.cxf.transport.http.HTTPConduit;

public class FreeIPATwo {

    private static final String KEYTAB_CONF = "un.security.jgss.login";

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, KeyManagementException,
            LoginException {

        setProperties();

        loginTest();
        WebClient wc = WebClient.create("https://olmo.tirasa.net/ipa/json");
        WebClient.getConfig(wc).getHttpConduit().setTlsClientParameters(clientParameters());

        KerberosAuthOutInterceptor kbInterceptor = new KerberosAuthOutInterceptor();

        AuthorizationPolicy policy = new AuthorizationPolicy();
        policy.setAuthorizationType(AUTH_TYPE_NEGOTIATE);
        policy.setAuthorization(KEYTAB_CONF);

        kbInterceptor.setPolicy(policy);
        kbInterceptor.setCredDelegation(true);
        kbInterceptor.setServicePrincipalName("ldap/olmo.tirasa.net");
        kbInterceptor.setRealm("TIRASA.NET");

        WebClient.getConfig(wc).getOutInterceptors().add(new LoggingOutInterceptor());
        WebClient.getConfig(wc).getOutInterceptors().add(kbInterceptor);

//        AuthorizationPolicy policy = new AuthorizationPolicy();
//        policy.setAuthorizationType(AUTH_TYPE_NEGOTIATE);
//        policy.setAuthorization(KEYTAB_CONF);
//        policy.setUserName("admin@TIRASA.NET");
//        policy.setPassword("password");
//
//        KerberosAuthOutInterceptor kbInterceptor = new KerberosAuthOutInterceptor();
//        kbInterceptor.setPolicy(policy);
//        kbInterceptor.setRealm("TIRASA.NET");
//        kbInterceptor.setServicePrincipalName("ldap/olmo.tirasa.net");
//        kbInterceptor.setCredDelegation(true);
//        WebClient.getConfig(wc).getOutInterceptors().add(kbInterceptor);
//        wc.header("referer", "https://olmo.tirasa.net/ipa");
//        wc.type(MediaType.APPLICATION_JSON);
//        wc.accept(MediaType.APPLICATION_JSON);
//        
        WebClient.getConfig(wc).getHttpConduit().getAuthorization().setAuthorizationType(AUTH_TYPE_NEGOTIATE);
        WebClient.getConfig(wc).getHttpConduit().getAuthorization().setAuthorization(KEYTAB_CONF);
        WebClient.getConfig(wc).getHttpConduit().getAuthorization().setUserName("admin@TIRASA.NET");
        WebClient.getConfig(wc).getHttpConduit().getAuthorization().setPassword("passowrd");
        WebClient.getConfig(wc).getHttpConduit().setAuthorization(policy);
//        printConduit(WebClient.getConfig(wc).getHttpConduit());
        Response r = wc.post("{\"method\":\"user_find\",\"params\":[[\"\"],{\"all\":\"true\"}],\"id\":0}");

        System.out.println("STREAM: " + r.getStatus());
        System.out.println("STREAM: " + r.getHeaders());
        System.out.println("STREAM: " + getStringFromInputStream((InputStream) r.getEntity()));
    }

    private static void printConduit(final HTTPConduit conduit) {
        System.out.println(">>>>>>>>>>> " + conduit.getAddress());
        System.out.println(">>>>>>>>>>> " + conduit.getBeanName());
        System.out.println(">>>>>>>>>>> " + conduit.getAuthorization().getAuthorizationType());
        System.out.println(">>>>>>>>>>> " + conduit.getAuthorization().getAuthorization());
        System.out.println(">>>>>>>>>>> " + conduit.getAuthorization().isSetAuthorization());
        System.out.println(">>>>>>>>>>> " + conduit.getAuthorization().isSetAuthorizationType());
        System.out.println(">>>>>>>>>>> " + conduit.getAuthorization().isSetPassword());
        System.out.println(">>>>>>>>>>> " + conduit.getAuthorization().isSetUserName());
    }

    private static void setProperties() throws LoginException {
        System.setProperty("java.security.auth.login.config", "/var/tmp/jass.conf");
        System.setProperty("java.security.krb5.realm", "TIRASA.NET");
        System.setProperty("java.security.krb5.kdc", "olmo.tirasa.net");
    }

    private static void loginTest() throws LoginException {
        LoginContext lc = new LoginContext(KEYTAB_CONF);
        lc.login();
        Subject serviceSubject = lc.getSubject();
        System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>> " + serviceSubject.toString());
    }

    private static TLSClientParameters clientParameters() throws NoSuchAlgorithmException, KeyManagementException {
        final TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {

            @Override
            public void checkClientTrusted(final X509Certificate[] chain, final String authType) {
            }

            @Override
            public void checkServerTrusted(final X509Certificate[] chain, final String authType) {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        }};

        final SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

        final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

        TLSClientParameters p = new TLSClientParameters();

        p.setDisableCNCheck(true);
        p.setSSLSocketFactory(sslSocketFactory);

        return p;
    }

    private static String getStringFromInputStream(InputStream is) {

        BufferedReader br = null;
        StringBuilder sb = new StringBuilder();

        String line;
        try {

            br = new BufferedReader(new InputStreamReader(is));
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return sb.toString();

    }
}
