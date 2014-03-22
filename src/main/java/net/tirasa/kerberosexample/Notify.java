package net.tirasa.kerberosexample;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.net.URL;

class Notify {

    static class MyAuthenticator extends Authenticator {

        @Override
        public PasswordAuthentication getPasswordAuthentication() {
            System.out.println("trying to authenticate");
            return new PasswordAuthentication("admin", "password".toCharArray());
        }
    }

    public static void main(String argv[]) throws Exception {
        // Construct data
        Authenticator.setDefault(new MyAuthenticator());
        URL url = new URL("https://olmo.tirasa.net/ipa/json");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setRequestMethod("GET");

        // Get the response
        BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String line;
        while ((line = rd.readLine()) != null) {
            System.out.println(line);
        }
        rd.close();

    }
}
