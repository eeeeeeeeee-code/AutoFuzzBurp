package AutoBurp.bypass;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import AutoBurp.bypass.beens.Browsers;
import AutoBurp.bypass.beens.MatchAndReplace;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ThreadPoolExecutor;

public class TLSContextMenuItemsProvider implements ContextMenuItemsProvider {
    private ThreadPoolExecutor taskEngine;
    
    private List<HttpRequestResponse> requestResponses;
    private MontoyaApi montoyaApi;

    public TLSContextMenuItemsProvider(ThreadPoolExecutor taskEngine, MontoyaApi montoyaApi) {
        this.taskEngine = taskEngine;
        this.montoyaApi = montoyaApi;
        this.requestResponses = new ArrayList<>();
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent contextMenuEvent) {
        if (contextMenuEvent.isFromTool(ToolType.LOGGER, ToolType.PROXY, ToolType.TARGET, ToolType.ORGANIZER)) {

            List<Component> menuItemList = new ArrayList<>();
            
            this.requestResponses = new ArrayList<>();

            if(contextMenuEvent.messageEditorRequestResponse().isPresent()) {
                MessageEditorHttpRequestResponse message = contextMenuEvent.messageEditorRequestResponse().get();
                this.requestResponses.add(message.requestResponse());
                String negotiation = Utilities.getComment(message.requestResponse());
                if(negotiation != null) {
                    JMenuItem negotiationItem = new JMenuItem(Utilities.getResourceString("negotiation"));
                    negotiationItem.addActionListener(e -> addManualSettings(negotiation));
                    menuItemList.add(negotiationItem);
                }
            } else {
                this.requestResponses = contextMenuEvent.selectedRequestResponses();
            }

            if(this.requestResponses.isEmpty()) return null;


            HttpRequestResponse requestResponse = this.requestResponses.get(0);
            String userAgent = requestResponse.request().header("User-Agent").value();
            if (userAgent == null || userAgent.isBlank()) {
                Arrays.stream(Browsers.values()).forEach(
                        browser -> {
                            JMenuItem item = new JMenuItem(browser.name);
                            item.addActionListener(e -> addTLSCiphers(browser));
                            menuItemList.add(item);
                        }
                );
            } else {
                Optional<Browsers> br = Arrays.stream(Browsers.values())
                        .filter(browsers -> userAgent.contains(browsers.name)).findAny();
                if (br.isPresent()) {
                    JMenuItem message = new JMenuItem(Utilities.getResourceString("message"));
                    message.addActionListener(e -> addTLSCiphers(br.get()));
                    menuItemList.add(message);
                } else {
                    Arrays.stream(Browsers.values()).forEach(
                            browser -> {
                                JMenuItem item = new JMenuItem(browser.name);
                                item.addActionListener(e -> addTLSCiphers(browser));
                                menuItemList.add(item);
                            }
                    );
                }
            }

            String menuLabel = Utilities.enabledHTTPDowngrade() ? "Enable " : "Disable ";
            JMenuItem downgradeMenu = new JMenuItem(menuLabel + Utilities.getResourceString("menu_downgrade"));
            downgradeMenu.addActionListener(e -> downgradeHttp());
            menuItemList.add(downgradeMenu);

            JMenuItem item = new JMenuItem(Utilities.getResourceString("menu_brute_force"));
            item.addActionListener(new TriggerCipherGuesser(taskEngine, this.requestResponses));
            menuItemList.add(item);


            return menuItemList;
        }

        return null;
    }

    public void downgradeHttp(){
        Utilities.updateHTTPSettings();
        
        
        if (!this.requestResponses.isEmpty()) {
            HttpRequestResponse requestResponse = this.requestResponses.get(0);
            String url = requestResponse.request().url();
            boolean isHttpDowngradeEnabled = !Utilities.enabledHTTPDowngrade(); 
            
            
            String userAgent = requestResponse.request().header("User-Agent").value();
            Browsers browser = Browsers.FIREFOX; 
            for (Browsers b : Browsers.values()) {
                if (userAgent != null && userAgent.contains(b.name)) {
                    browser = b;
                    break;
                }
            }
            
            DomainSettingsManager.addDomainSettings(
                url,
                browser,
                Constants.BROWSERS_PROTOCOLS.get(browser.name),
                Constants.BROWSERS_CIPHERS.get(browser.name),
                isHttpDowngradeEnabled
            );
        }
    }

    public void addTLSCiphers(Browsers browser){
        Utilities.updateTLSSettingsSync(Constants.BROWSERS_PROTOCOLS.get(browser.name), Constants.BROWSERS_CIPHERS.get(browser.name));
        Utilities.updateProxySettingsSync(MatchAndReplace.create(browser));
        
        
        if (!this.requestResponses.isEmpty()) {
            HttpRequestResponse requestResponse = this.requestResponses.get(0);
            String url = requestResponse.request().url();
            boolean isHttpDowngradeEnabled = Utilities.enabledHTTPDowngrade();
            
            DomainSettingsManager.addDomainSettings(
                url,
                browser,
                Constants.BROWSERS_PROTOCOLS.get(browser.name),
                Constants.BROWSERS_CIPHERS.get(browser.name),
                isHttpDowngradeEnabled
            );
        }
    }
    public void addManualSettings(String negotiation){
        Utilities.montoyaApi.burpSuite().importProjectOptionsFromJson(negotiation);
    }
}
