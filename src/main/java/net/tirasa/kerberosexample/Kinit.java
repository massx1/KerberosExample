package net.tirasa.kerberosexample;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import javax.security.auth.Subject;
import javax.security.auth.kerberos.KeyTab;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import sun.security.krb5.Config;
import sun.security.krb5.KrbAsReqBuilder;
import sun.security.krb5.KrbException;
import sun.security.krb5.PrincipalName;
import sun.security.krb5.RealmException;
import sun.security.krb5.internal.HostAddresses;
import sun.security.krb5.internal.KDCOptions;
import sun.security.krb5.internal.Krb5;
import sun.security.krb5.internal.ccache.CredentialsCache;
import sun.security.util.Password;

public class Kinit {

    private static final boolean DEBUG = Krb5.DEBUG;

    /**
     * The main method is used to accept user command line input for ticket request.
     * <p>
     * Usage: kinit [-A] [-f] [-p] [-c cachename] [[-k [-t keytab_file_name]] [principal] [password]
     * <ul>
     * <li> -A do not include addresses
     * <li> -f forwardable
     * <li> -p proxiable
     * <li> -c cache name (i.e., FILE://c:\temp\mykrb5cc)
     * <li> -k use keytab
     * <li> -t keytab file name
     * <li> principal the principal name (i.e., duke@java.sun.com)
     * <li> password the principal's Kerberos password
     * </ul>
     * <p>
     * Use java sun.security.krb5.tools.Kinit -help to bring up help menu.
     * <p>
     * We currently support only file-based credentials cache to store the tickets obtained from the KDC. By default,
     * for all Unix platforms a cache file named /tmp/krb5cc_&lt;uid&gt will be generated. The &lt;uid&gt is the numeric
     * user identifier. For all other platforms, a cache file named &lt;USER_HOME&gt/krb5cc_&lt;USER_NAME&gt would be
     * generated.
     * <p>
     * &lt;USER_HOME&gt is obtained from <code>java.lang.System</code> property <i>user.home</i>. &lt;USER_NAME&gt is
     * obtained from <code>java.lang.System</code> property <i>user.name</i>. If &lt;USER_HOME&gt is null the cache file
     * would be stored in the current directory that the program is running from. &lt;USER_NAME&gt is operating system's
     * login username. It could be different from user's principal name.
     * </p>
     * <p>
     * For instance, on Windows NT, it could be c:\winnt\profiles\duke\krb5cc_duke, in which duke is the
     * &lt;USER_NAME&gt, and c:\winnt\profile\duke is the &lt;USER_HOME&gt.
     * <p>
     * A single user could have multiple principal names, but the primary principal of the credentials cache could only
     * be one, which means one cache file could only store tickets for one specific user principal. If the user switches
     * the principal name at the next Kinit, the cache file generated for the new ticket would overwrite the old cache
     * file by default. To avoid overwriting, you need to specify a different cache file name when you request a new
     * ticket.
     * </p>
     * <p>
     * You can specify the location of the cache file by using the -c option
     *
     */
    public static void main(String[] args) {

        System.setProperty("java.security.auth.login.config", "/var/tmp/jass.conf");
        System.setProperty("sun.security.krb5.debug", "true");
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
        System.setProperty("java.security.krb5.conf", "/etc/krb5.conf");
        System.setProperty("java.security.krb5.realm", "TIRASA.NET");
        System.setProperty("java.security.krb5.kdc", "olmo.tirasa.net");

        try {
            Kinit self = new Kinit();
        } catch (Exception e) {
            String msg = null;
            if (e instanceof KrbException) {
                msg = ((KrbException) e).krbErrorMessage() + " " + ((KrbException) e).returnCodeMessage();
            } else {
                msg = e.getMessage();
            }
            if (msg != null) {
                System.err.println("Exception: " + msg);
            } else {
                System.out.println("Exception: " + e);
            }
            e.printStackTrace();
            System.exit(-1);
        }
        return;
    }

    /**
     * Constructs a new Kinit object.
     *
     * @param args array of ticket request options. Avaiable options are: -f, -p, -c, principal, password.
     * @exception IOException if an I/O error occurs.
     * @exception RealmException if the Realm could not be instantiated.
     * @exception KrbException if error occurs during Kerberos operation.
     */
    private Kinit() throws IOException, RealmException, KrbException, LoginException {

//        LoginContext lc = new LoginContext("KerberosClientKeyTabAdmin");
//        lc.login();
//        Subject serviceSubject = lc.getSubject();

        PrincipalName principal = new PrincipalName("HTTP/ebano.tirasa.net");
        String princName = principal.toString();
        KrbAsReqBuilder builder;
        if (DEBUG) {
            System.out.println("Principal is " + principal);
        }
        if (DEBUG) {
            System.out.println(">>> Kinit using keytab");
        }
        if (princName == null) {
            throw new IllegalArgumentException("Principal name must be specified.");
        }
        String ktabName = "/var/tmp/ebano.keytab";
        if (ktabName != null) {
            if (DEBUG) {
                System.out.println(
                        ">>> Kinit keytab file name: " + ktabName);
            }
        }

        builder = new KrbAsReqBuilder(principal, ktabName == null
                ? KeyTab.getInstance()
                : KeyTab.getInstance(new File(ktabName)));

        KDCOptions opt = new KDCOptions();
        setOptions(KDCOptions.FORWARDABLE, 1, opt);
        setOptions(KDCOptions.PROXIABLE, 0, opt);
        builder.setOptions(opt);
        String realm = "TIRASA.NET";
        if (realm == null) {
            realm = Config.getInstance().getDefaultRealm();
        }

        if (DEBUG) {
            System.out.println(">>> Kinit realm name is " + realm);
        }

        PrincipalName sname = new PrincipalName("krbtgt" + "/" + realm,
                PrincipalName.KRB_NT_SRV_INST);
        sname.setRealm(realm);
        builder.setTarget(sname);

        if (DEBUG) {
            System.out.println(">>> Creating KrbAsReq");
        }

//        if (options.getAddressOption()) {
//            builder.setAddresses(HostAddresses.getLocalAddresses());
//        }
        builder.action();

        sun.security.krb5.internal.ccache.Credentials credentials = builder.getCCreds();
        builder.destroy();

        // we always create a new cache and store the ticket we get
        CredentialsCache cache = CredentialsCache.create(principal);
        cache.update(credentials);
        cache.save();
    }

    private static void setOptions(int flag, int option, KDCOptions opt) {
        switch (option) {
            case 0:
                break;
            case -1:
                opt.set(flag, false);
                break;
            case 1:
                opt.set(flag, true);
        }
    }
}
