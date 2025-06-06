package AutoBurp.bypass.beens;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class DomainSettings {
    private String domain;
    private String browser;
    private String[] protocols;
    private String[] ciphers;
    private boolean httpDowngrade;
    private String timestamp;

    public DomainSettings(String domain, String browser, String[] protocols, String[] ciphers, boolean httpDowngrade) {
        this.domain = domain;
        this.browser = browser;
        this.protocols = protocols;
        this.ciphers = ciphers;
        this.httpDowngrade = httpDowngrade;
        this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }

    public String getDomain() {
        return domain;
    }

    public String getBrowser() {
        return browser;
    }

    public String[] getProtocols() {
        return protocols;
    }

    public String[] getCiphers() {
        return ciphers;
    }

    public boolean isHttpDowngrade() {
        return httpDowngrade;
    }

    public String getTimestamp() {
        return timestamp;
    }

    @Override
    public String toString() {
        return String.format("域名: %s, 浏览器: %s, HTTP降级: %s, 时间: %s", 
                domain, browser, httpDowngrade ? "是" : "否", timestamp);
    }
}