package AutoBurp.fingerprint.util;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class HTTPUtils {
    
    public static Map<String, Object> makeGetRequest(String getUrl, IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks) {
        
        String host;
        int port;
        String protocol;
        String path;
        
        try {
            
            URL url = new URL(getUrl);
            
            protocol = url.getProtocol();
            host = url.getHost();
            port = url.getPort();
            
            if (port == -1 && protocol.equalsIgnoreCase("http")) {
                port = 80;
            } else if (port == -1 && protocol.equalsIgnoreCase("https")) {
                port = 443;
            }
            
            path = url.getPath();
            if (path.isEmpty()) {
                path = "/";
            }
            
            if (url.getQuery() != null) {
                path += "?" + url.getQuery();
            }
        } catch (Exception e) {
            
            callbacks.printError("Invalid URL: " + getUrl);
            return null;
        }
        
        
        IHttpService httpService = helpers.buildHttpService(host, port, protocol);
        
        
        String request = "GET " + path + " HTTP/1.1\r\n" +
                "Host: " + host + "\r\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36\r\n" +
                "Accept: */*\r\n" +
                "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n" +
                "Connection: close\r\n" +
                "\r\n";
        
        byte[] requestBytes = request.getBytes();
        
        
        IHttpRequestResponse response = callbacks.makeHttpRequest(httpService, requestBytes);
        
        
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("responseRequest", response);
        responseData.put("isFindUrl", true);
        responseData.put("method", "GET");
        
        return responseData;
    }
}