package AutoBurp.bypass;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import AutoBurp.bypass.beens.Browsers;
import AutoBurp.bypass.beens.DomainSettings;
import AutoBurp.bypass.beens.MatchAndReplace;

import java.lang.reflect.Type;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class DomainSettingsManager {
    private static final String SETTINGS_KEY = "domain_tls_settings";
    private static List<DomainSettings> domainSettingsList = new ArrayList<>();
    private static MontoyaApi montoyaApi;
    private static Gson gson = new Gson();

    public static void initialize(MontoyaApi api) {
        montoyaApi = api;
        loadSettings();
    }

    public static void addDomainSettings(String url, Browsers browser, String[] protocols, String[] ciphers, boolean httpDowngrade) {
        try {
            String domain = extractDomain(url);
            if (domain == null || domain.isEmpty()) {
                return;
            }

            
            Optional<DomainSettings> existingSettings = domainSettingsList.stream()
                    .filter(settings -> settings.getDomain().equals(domain))
                    .findFirst();

            if (existingSettings.isPresent()) {
                
                domainSettingsList.remove(existingSettings.get());
            }

            
            DomainSettings newSettings = new DomainSettings(
                    domain, 
                    browser.name, 
                    protocols, 
                    ciphers, 
                    httpDowngrade
            );
            domainSettingsList.add(newSettings);
            saveSettings();
            
            
            Utilities.updateTLSSettingsSync(protocols, ciphers);
            Utilities.updateProxySettingsSync(MatchAndReplace.create(browser));
            
            
            if (Utilities.enabledHTTPDowngrade() != httpDowngrade) {
                Utilities.updateHTTPSettings();
            }
            

        } catch (Exception e) {
            Utilities.error("添加域名设置失败: " + e.getMessage());
        }
    }
    
    public static void updateDomainSettings(String domain, Browsers browser, String[] protocols, String[] ciphers, boolean httpDowngrade) {
        
        Optional<DomainSettings> existingSettings = domainSettingsList.stream()
                .filter(settings -> settings.getDomain().equals(domain))
                .findFirst();

        if (existingSettings.isPresent()) {
            
            domainSettingsList.remove(existingSettings.get());
            
            
            DomainSettings newSettings = new DomainSettings(
                    domain, 
                    browser.name, 
                    protocols, 
                    ciphers, 
                    httpDowngrade
            );
            domainSettingsList.add(newSettings);
            saveSettings();
            
            
            Utilities.updateTLSSettingsSync(protocols, ciphers);
            Utilities.updateProxySettingsSync(MatchAndReplace.create(browser));
            
            
            if (Utilities.enabledHTTPDowngrade() != httpDowngrade) {
                Utilities.updateHTTPSettings();
            }
            
            Utilities.log("已更新并应用域名 " + domain + " 的 TLS 设置");
        }
    }
    
    public static void removeDomainSettings(String domain) {
        boolean removed = domainSettingsList.removeIf(settings -> settings.getDomain().equals(domain));
        if (removed) {
            saveSettings();
            
            Utilities.loadTLSSettings();

        }
    }
    
    public static List<DomainSettings> getAllDomainSettings() {
        return new ArrayList<>(domainSettingsList);
    }
    
    public static Optional<DomainSettings> getDomainSettings(String domain) {
        return domainSettingsList.stream()
                .filter(settings -> settings.getDomain().equals(domain))
                .findFirst();
    }


    public static void applyDomainSettings(String domain) {
        Optional<DomainSettings> settings = getDomainSettings(domain);
        if (settings.isPresent()) {
            DomainSettings domainSettings = settings.get();
            
            
            Browsers browser = Browsers.valueOf(domainSettings.getBrowser());
            
            
            Utilities.updateTLSSettingsSync(domainSettings.getProtocols(), domainSettings.getCiphers());
            
            
            Utilities.updateProxySettingsSync(MatchAndReplace.create(browser));
            
            
            if (Utilities.enabledHTTPDowngrade() != domainSettings.isHttpDowngrade()) {
                Utilities.updateHTTPSettings();
            }
            

        }
    }

    private static void saveSettings() {
        String serializedSettings = gson.toJson(domainSettingsList);
        montoyaApi.persistence().preferences().setString(SETTINGS_KEY, serializedSettings);
    }

    private static void loadSettings() {
        String serializedSettings = montoyaApi.persistence().preferences().getString(SETTINGS_KEY);
        if (serializedSettings != null && !serializedSettings.isEmpty()) {
            Type listType = new TypeToken<ArrayList<DomainSettings>>(){}.getType();
            domainSettingsList = gson.fromJson(serializedSettings, listType);
        }
    }
    
    private static String extractDomain(String url) {
        try {
            if (!url.startsWith("http")) {
                url = "http://" + url;
            }
            URI uri = new URI(url);
            String domain = uri.getHost();
            return domain;
        } catch (Exception e) {
            return url;
        }
    }
}