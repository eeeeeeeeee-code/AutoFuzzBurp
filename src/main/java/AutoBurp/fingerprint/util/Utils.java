package AutoBurp.fingerprint.util;

import java.net.URL;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Utils {
    

    
    public static String getUriExt(String url) {
        try {
            String path = new URL(url).getPath();
            int lastDotPos = path.lastIndexOf('.');
            if (lastDotPos > 0) {
                return path.substring(lastDotPos + 1).toLowerCase();
            }
        } catch (Exception e) {
            
        }
        return "";
    }
    
    
    public static String getTitle(String html) {
        Pattern pattern = Pattern.compile("<title>(.*?)</title>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        Matcher matcher = pattern.matcher(html);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return "";
    }
    
    public static String getFaviconHash(byte[] data) {
        try {
            
            String base64Favicon = Base64.getEncoder().encodeToString(data);
            
            
            String formattedBase64Favicon = formatBase64(base64Favicon);
            
            
            return String.valueOf(MurmurHash3.hash32(
                    formattedBase64Favicon.getBytes(), 
                    0, 
                    formattedBase64Favicon.length(), 
                    0));
        } catch (Exception e) {
            return "0";
        }
    }
    
    
    private static String formatBase64(String base64) {
        Pattern pattern = Pattern.compile(".{76}");
        Matcher matcher = pattern.matcher(base64);
        StringBuilder formattedBase64 = new StringBuilder();
        
        while (matcher.find()) {
            formattedBase64.append(matcher.group()).append("\n");
        }
        
        int remainder = base64.length() % 76;
        if (remainder > 0) {
            formattedBase64.append(base64.substring(base64.length() - remainder)).append("\n");
        }
        
        return formattedBase64.toString();
    }
    
    
    public static Set<String> extractUrlsFromHtml(String baseUrl, String html) {
        Set<String> urls = new HashSet<>();
        
        
        Pattern hrefPattern = Pattern.compile("href=[\"'](.*?)[\"']", Pattern.CASE_INSENSITIVE);
        Matcher hrefMatcher = hrefPattern.matcher(html);
        while (hrefMatcher.find()) {
            String url = hrefMatcher.group(1);
            if (!url.startsWith("#") && !url.startsWith("javascript:")) {
                urls.add(processUrl(baseUrl, url));
            }
        }
        
        
        Pattern srcPattern = Pattern.compile("src=[\"'](.*?)[\"']", Pattern.CASE_INSENSITIVE);
        Matcher srcMatcher = srcPattern.matcher(html);
        while (srcMatcher.find()) {
            String url = srcMatcher.group(1);
            urls.add(processUrl(baseUrl, url));
        }
        
        return urls;
    }
    
    
    public static String processUrl(String baseUrl, String relativeUrl) {
        try {
            URL base = new URL(baseUrl);
            URL absolute = new URL(base, relativeUrl);
            return absolute.toString();
        } catch (Exception e) {
            return relativeUrl;
        }
    }
    
    
    public static Set<String> findUrls(URL baseUrl, String text) {
        Set<String> urls = new HashSet<>();
        
        
        Pattern urlPattern = Pattern.compile("(https?://[^\\s\"'<>]+)", Pattern.CASE_INSENSITIVE);
        Matcher urlMatcher = urlPattern.matcher(text);
        
        while (urlMatcher.find()) {
            urls.add(urlMatcher.group(1));
        }
        
        return urls;
    }
    
    
    private static class MurmurHash3 {
        public static int hash32(byte[] data, int offset, int length, int seed) {
            int h1 = seed;
            int c1 = 0xcc9e2d51;
            int c2 = 0x1b873593;
            int roundedEnd = offset + (length & 0xfffffffc);
            
            for (int i = offset; i < roundedEnd; i += 4) {
                int k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | 
                         ((data[i + 2] & 0xff) << 16) | ((data[i + 3] & 0xff) << 24);
                
                k1 *= c1;
                k1 = (k1 << 15) | (k1 >>> 17);
                k1 *= c2;
                
                h1 ^= k1;
                h1 = (h1 << 13) | (h1 >>> 19);
                h1 = h1 * 5 + 0xe6546b64;
            }
            
            int k1 = 0;
            switch (length & 0x03) {
                case 3:
                    k1 = (data[roundedEnd + 2] & 0xff) << 16;
                case 2:
                    k1 |= (data[roundedEnd + 1] & 0xff) << 8;
                case 1:
                    k1 |= (data[roundedEnd] & 0xff);
                    k1 *= c1;
                    k1 = (k1 << 15) | (k1 >>> 17);
                    k1 *= c2;
                    h1 ^= k1;
            }
            
            h1 ^= length;
            h1 ^= h1 >>> 16;
            h1 *= 0x85ebca6b;
            h1 ^= h1 >>> 13;
            h1 *= 0xc2b2ae35;
            h1 ^= h1 >>> 16;
            
            return h1;
        }
    }
}