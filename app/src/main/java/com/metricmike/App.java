package com.metricmike;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLContext;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

public class App {
    public String getGreeting() {
        return "Hello World!";
    }

    public static void main(String[] args) {
        setJavaNetworkingProperties();
        loadBCProviders();
        System.out.println(new App().getGreeting());
    }

    // Set Java networking properties
    public static void setJavaNetworkingProperties() {
        // set short DNS cache for better compatibility with ephemeral services
        // This may not work if the JVM has already made network calls
        Security.setProperty("networkaddress.cache.ttl", "60");

        // Assume no IPv6 support, don't wait for DNSv6 answers
        System.setProperty("java.net.preferIPv4Stack","true");
    }

    // Load BC Providers
    public static void loadBCProviders() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            BouncyCastleProvider provider = new BouncyCastleProvider();
            Security.addProvider(provider);
            // have to chain both BC providers,  so it doesn't conflict with JVM's default
            Security.addProvider(new BouncyCastleJsseProvider(provider));
        }
    }

    // Create HTTP Client
    public static HttpClientBuilder createHttpClientBuilder() throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        // Configure with client cert, custom ca bundle
        // no dns caching
        SSLContext sslContext = SSLContexts.custom()
                .loadKeyMaterial(KeyStore.getInstance("PKCS12"), null)
                .loadTrustMaterial(KeyStore.getInstance("PKCS12"), null)
                .build();

        // CNSA-compatible protocols/ciphers
        String[] supportedProtocols = {"TLSv1.3", "TLSv1.2"};
        String[] supportedCipherSuites = {"TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"};
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
            sslContext,
            supportedProtocols,
            supportedCipherSuites,
            NoopHostnameVerifier.INSTANCE);
        
        // Set all timeouts to 5 sec
        RequestConfig defaultRequestConfig = RequestConfig.custom()
            .setConnectTimeout(5000)
            .setSocketTimeout(5000)
            .setConnectionRequestTimeout(5000)
            .build();

        // Don't verify hostnames, follow redirects, store cookies
        HttpClientBuilder httpClientBuilder = HttpClients.custom()
            .setDefaultRequestConfig(defaultRequestConfig)
            .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
            .setRedirectStrategy(LaxRedirectStrategy.INSTANCE)
            .setDefaultCookieStore(new BasicCookieStore())
            .setSSLSocketFactory(sslsf);

        return httpClientBuilder;
    };

    public static Map<Integer, String> consumeHttpsUrl(String url, String method, Map<String, String> params) throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        Map<Integer, String> result = new HashMap<>();
        HttpClientBuilder clientBuilder = createHttpClientBuilder();

        try {
            // Create the HTTP request based on the method
            HttpRequestBase request;
            switch (method.toUpperCase()) {
                case "GET":
                    request = new HttpGet(url);
                    break;
                case "POST":
                    request = new HttpPost(url);
                    break;
                case "PUT":
                    request = new HttpPut(url);
                    break;
                case "DELETE":
                    request = new HttpDelete(url);
                    break;
                default:
                    throw new IllegalArgumentException("Invalid HTTP method: " + method);
            }

            // Add any parameters to the request
            if (params != null) {
                for (Map.Entry<String, String> entry : params.entrySet()) {
                    request.addHeader(entry.getKey(), entry.getValue());
                }
            }

            // Execute the request and get the response
            HttpResponse response = clientBuilder.build().execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            String responseBody = entity != null ? EntityUtils.toString(entity) : null;

            // Store the status code and response body in the result map
            result.put(statusCode, responseBody);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return result;
    }
}

