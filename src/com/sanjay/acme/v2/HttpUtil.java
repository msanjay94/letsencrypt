package com.sanjay.acme.v2;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HttpUtil {
	static HttpURLConnection getConnection(String url) throws MalformedURLException, IOException {
		try {
	        SSLContext ctx = SSLContext.getInstance("TLS");
	        ctx.init(new KeyManager[0], new TrustManager[] { new X509TrustManager() {
				
				@Override
				public X509Certificate[] getAcceptedIssuers() {
					// TODO Auto-generated method stub
					return null;
				}
				
				@Override
				public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
					// TODO Auto-generated method stub
					
				}
				
				@Override
				public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
					// TODO Auto-generated method stub
					
				}
			}}, new SecureRandom());
	        SSLContext.setDefault(ctx);
	    } catch (Exception e) {
	        throw new RuntimeException(e);
	    }
		System.out.println("Opening connection with : "+url);
		HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
		connection.setConnectTimeout(5000);
		connection.setRequestProperty("Content-Type", "application/jose+json");
		return connection;
	}
	
	static HttpURLConnection postData(String url, String requestData) throws MalformedURLException, IOException {
		HttpURLConnection connection = getConnection(url);
		connection.setDoOutput(true);
		connection.setRequestMethod("POST");
		DataOutputStream wr = new DataOutputStream(connection.getOutputStream());
        try {
        		wr.writeBytes(requestData);
        } finally {
            	wr.flush();
	        	wr.close();
	    }
        return connection;
	}
	
	static Map<String, List<String>> printHeaders(HttpURLConnection connection) {
		System.out.println("Response Headers : ");
		Map<String, List<String>> headers = connection.getHeaderFields();
		for (String headerName :  headers.keySet()) {
			System.out.println(headerName + " - \t" + headers.get(headerName));
		}
		return headers;
	}
}
