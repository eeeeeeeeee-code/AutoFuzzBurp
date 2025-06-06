package AutoBurp.bypass;

import AutoBurp.fingerprint.FingerPrintScanner;
import AutoBurp.fingerprint.model.FingerPrintRule;
import AutoBurp.fingerprint.ui.FingerPrintTab;
import AutoBurp.fuzzer.phone.PhoneFuzzer;
import AutoBurp.fuzzer.upload.UploadFuzzer;
import burp.*;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import AutoBurp.bypass.beens.Browsers;
import AutoBurp.bypass.beens.MatchAndReplace;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.*;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class BypassBotDetection implements BurpExtension, IBurpExtender, IIntruderPayloadGeneratorFactory, IProxyListener, IExtensionStateListener {
    private MontoyaApi montoyaApi;
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private FingerPrintTab fingerPrintTab;
    private FingerPrintScanner fingerPrintScanner;
    private List<FingerPrintRule> fingerprintRules;
    private Set<String> scannedUrls = Collections.synchronizedSet(new HashSet<>());
    private final ScheduledExecutorService memoryMonitor = Executors.newSingleThreadScheduledExecutor();
    private final AtomicInteger requestCount = new AtomicInteger(0);
    private final AtomicInteger successCount = new AtomicInteger(0);

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        montoyaApi.extension().setName("综合Bypass");
        try {
            new Utilities(montoyaApi);
            BlockingQueue<Runnable> tasks = new LinkedBlockingQueue<>();
            ThreadPoolExecutor taskEngine = new ThreadPoolExecutor(1, 1, 1, TimeUnit.MINUTES, tasks);
            Utilities.saveTLSSettings();
            
            
            DomainSettingsManager.initialize(montoyaApi);
            
            
            montoyaApi.userInterface().registerContextMenuItemsProvider(new TLSContextMenuItemsProvider(taskEngine, montoyaApi));
            
            
            DomainSettingsPanel settingsPanel = new DomainSettingsPanel(montoyaApi);
            montoyaApi.userInterface().registerSuiteTab("TLS WAF", settingsPanel);
            
            montoyaApi.extension().registerUnloadingHandler(()-> {
                Utilities.unloaded.set(true);
                try {
                    taskEngine.getQueue().clear();
                    taskEngine.shutdown();
                    
                    
                    memoryMonitor.shutdownNow();
                    if (fingerPrintScanner != null) {
                        fingerPrintScanner.shutdown();
                    }
                }finally {
                    Utilities.loadTLSSettings();

                }
            });
            
            Thread thread = new Thread(() -> {
                try {
                    Thread.sleep(3000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                
                Utilities.updateTLSSettings(Constants.BROWSERS_PROTOCOLS.get(Browsers.FIREFOX.name), Constants.BROWSERS_CIPHERS.get(Browsers.FIREFOX.name));
                Utilities.updateProxySettings(MatchAndReplace.create(Browsers.FIREFOX));
            });
            thread.start();

            montoyaApi.logging().logToOutput("Auto Fuzz & FingerPrint loaded successfully - Author: e0e1 - Version: 2.0");
            montoyaApi.logging().logToOutput("github: https://github.com/eeeeeeeeee-code/AutoFuzzBurp");

        } catch (Exception e) {
            montoyaApi.logging().logToError(e.getMessage());
        }
    }
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.setExtensionName("Bot Detection Bypass & Auto Fuzz");

        
        callbacks.registerIntruderPayloadGeneratorFactory(this);
        
        
        PhoneFuzzer phoneFuzzer = new PhoneFuzzer(this.helpers, callbacks);
        callbacks.registerIntruderPayloadGeneratorFactory(phoneFuzzer);

        
        loadFingerPrintRules();
        
        
        fingerPrintTab = new FingerPrintTab(callbacks, helpers);
        callbacks.addSuiteTab(fingerPrintTab);
        
        
        fingerPrintTab.setRulePanel(fingerprintRules);
        
        
        fingerPrintScanner = new FingerPrintScanner(callbacks, helpers, fingerprintRules, fingerPrintTab, scannedUrls, requestCount, successCount);
        
        
        fingerPrintTab.setScanner(fingerPrintScanner);

        
        callbacks.registerProxyListener(this);
        
        
        callbacks.registerExtensionStateListener(this);
        
        
        startMemoryMonitor();
    }

    private void loadFingerPrintRules() {
        try {
            
            File localFile = new File("finger-important.json");
            InputStream inputStream = null;
            
            if (localFile.exists() && localFile.isFile()) {
                
                inputStream = new FileInputStream(localFile);

            } else {
                
                ClassLoader classLoader = getClass().getClassLoader();
                inputStream = classLoader.getResourceAsStream("conf/finger-important.json");
                
                if (inputStream != null) {
                    
                    try (InputStream resourceStream = classLoader.getResourceAsStream("conf/finger-important.json");
                         FileOutputStream outputStream = new FileOutputStream(localFile)) {
                        
                        if (resourceStream != null) {
                            byte[] buffer = new byte[1024];
                            int length;
                            while ((length = resourceStream.read(buffer)) > 0) {
                                outputStream.write(buffer, 0, length);
                            }

                            
                            
                            inputStream = new FileInputStream(localFile);
                        }
                    } catch (Exception e) {
                        stderr.println("[!] 复制资源文件到当前目录失败: " + e.getMessage());
                    }
                }
            }
            
            if (inputStream == null) {
                stderr.println("[!] 无法加载指纹规则文件");
                fingerprintRules = new ArrayList<>();
                return;
            }

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
                Gson gson = new Gson();
                Type fingerprintRuleListType = new TypeToken<Map<String, List<FingerPrintRule>>>(){}.getType();
                Map<String, List<FingerPrintRule>> rulesWrapper = gson.fromJson(reader, fingerprintRuleListType);
                fingerprintRules = rulesWrapper.get("fingerprint");

            }
        } catch (Exception e) {
            stderr.println("[!] 加载指纹规则失败: " + e.getMessage());
            e.printStackTrace(stderr);
            fingerprintRules = new ArrayList<>();
        }
    }

    private void startMemoryMonitor() {
        memoryMonitor.scheduleAtFixedRate(() -> {
            Runtime runtime = Runtime.getRuntime();
            long usedMemory = runtime.totalMemory() - runtime.freeMemory();
            long maxMemory = runtime.maxMemory();
            double memoryUsageRatio = (double) usedMemory / maxMemory;
            
            if (memoryUsageRatio > 0.7) {
                System.gc();
            }
        }, 30, 30, TimeUnit.SECONDS);
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (!messageIsRequest) {
            fingerPrintScanner.processMessage(message);
        }
    }

    @Override
    public void extensionUnloaded() {
        memoryMonitor.shutdownNow();
        
        if (fingerPrintScanner != null) {
            fingerPrintScanner.shutdown();
        }
        



    }

    @Override
    public String getGeneratorName() {
        return "Upload Auto Fuzz";
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        return new UploadFuzzer(this.helpers, attack, this.callbacks);
    }
}