package AutoBurp.fingerprint;

import AutoBurp.fingerprint.model.FingerPrintRule;
import AutoBurp.fingerprint.model.TableLogModel;
import AutoBurp.fingerprint.ui.FingerPrintTab;
import AutoBurp.fingerprint.util.FingerPrintUtils;
import AutoBurp.fingerprint.util.HTTPUtils;
import AutoBurp.fingerprint.util.Utils;
import burp.*;

import java.io.PrintWriter;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class FingerPrintScanner {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private List<FingerPrintRule> fingerprintRules; 
    private final FingerPrintTab fingerPrintTab;
    private final Set<String> scannedUrls;
    private final AtomicInteger requestCount;
    private final AtomicInteger successCount;
    private final ThreadPoolExecutor executorService;
    private final Object scanLock = new Object();
    private volatile boolean acceptingNewTasks;

    
    private final static String[] STATIC_FILE_EXT = new String[]{
            "png", "jpg", "jpeg", "gif", "pdf", "bmp", "css", "woff", "woff2", 
            "ttf", "otf", "ttc", "svg", "psd", "exe", "zip", "rar", "7z", 
            "msi", "tar", "gz", "mp3", "mp4", "mkv", "swf", "iso"
    };

    
    private final static String[] STATIC_URL_EXT = new String[]{
            "js", "ppt", "pptx", "doc", "docx", "xls", "xlsx", "cvs"
    };

    public FingerPrintScanner(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, 
                             List<FingerPrintRule> fingerprintRules, FingerPrintTab fingerPrintTab,
                             Set<String> scannedUrls, AtomicInteger requestCount, AtomicInteger successCount) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.fingerprintRules = fingerprintRules;
        this.fingerPrintTab = fingerPrintTab;
        this.scannedUrls = scannedUrls;
        this.requestCount = requestCount;
        this.successCount = successCount;
        
        
        this.acceptingNewTasks = fingerPrintTab.isScanEnabled();
        
        
        int coreCount = Runtime.getRuntime().availableProcessors();
        coreCount = Math.max(coreCount, 10);
        int maxPoolSize = coreCount * 2;
        
        executorService = new ThreadPoolExecutor(
                coreCount,
                maxPoolSize,
                60L,
                TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(),
                Executors.defaultThreadFactory(),
                new ThreadPoolExecutor.CallerRunsPolicy()
        );
        


    }

    public void processMessage(IInterceptedProxyMessage message) {
        
        if (!fingerPrintTab.isScanEnabled() || !acceptingNewTasks) {

            return;
        }
        
        IHttpRequestResponse requestResponse = message.getMessageInfo();
        IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
        String url = requestInfo.getUrl().toString();
        
        
        fingerPrintTab.updateRequestCount(requestCount.incrementAndGet());
        
        
        if (scannedUrls.contains(url)) {
            return;
        }
        
        
        if (isStaticFile(url) && !url.contains("favicon.") && !url.contains(".ico")) {

            return;
        }
        
        
        synchronized (scanLock) {
            if (scannedUrls.contains(url)) {
                return;
            }
            scannedUrls.add(url);
        }
        
        
        if (!fingerPrintTab.isScanEnabled() || !acceptingNewTasks) {

            return;
        }
        
        
        executorService.submit(() -> {
            try {
                
                if (!fingerPrintTab.isScanEnabled()) {

                    return;
                }
                processUrl(message, requestResponse, url);
            } catch (Exception e) {
                callbacks.printError("[!] Error processing URL " + url + ": " + e.getMessage());
                e.printStackTrace(new PrintWriter(callbacks.getStderr(), true));
            }
        });
    }
    
    private void processUrl(IInterceptedProxyMessage message, IHttpRequestResponse requestResponse, String url) {
        
        if (!fingerPrintTab.isScanEnabled()) {

            return;
        }
        
        
        Map<String, Object> totalUrlResponse = new HashMap<>();
        
        
        Map<String, Object> originalData = new HashMap<>();
        originalData.put("responseRequest", requestResponse);
        originalData.put("isFindUrl", false);
        originalData.put("method", helpers.analyzeRequest(requestResponse).getMethod());
        totalUrlResponse.put(url, originalData);
        
        
        byte[] responseBytes = requestResponse.getResponse();
        if (responseBytes != null && responseBytes.length > 0 && !url.contains("favicon.") && !url.contains(".ico")) {
            IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
            String mime = responseInfo.getInferredMimeType().toLowerCase();
            URL urlObj = helpers.analyzeRequest(requestResponse).getUrl();
            
            
            Set<String> urlSet = new HashSet<>(Utils.extractUrlsFromHtml(url, new String(responseBytes)));
            
            
            if (mime.equals("script") || mime.equals("html") || url.contains(".htm") || isExtractableUrl(url)) {
                urlSet.addAll(Utils.findUrls(urlObj, new String(responseBytes)));
            }
            

            
            
            for (String extractedUrl : urlSet) {
                
                synchronized (scanLock) {
                    if (scannedUrls.contains(extractedUrl)) {
                        continue;
                    }
                    scannedUrls.add(extractedUrl);
                }
                
                Map<String, Object> responseData = HTTPUtils.makeGetRequest(extractedUrl, helpers, callbacks);
                if (responseData != null) {
                    totalUrlResponse.put(extractedUrl, responseData);
                }
            }
        }
        

        
        
        for (Map.Entry<String, Object> entry : totalUrlResponse.entrySet()) {
            
            if (!fingerPrintTab.isScanEnabled()) {

                return;
            }
            
            String oneUrl = entry.getKey();
            Object value = entry.getValue();
            
            if (value instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> oneResult = (Map<String, Object>) value;
                IHttpRequestResponse oneRequestResponse = (IHttpRequestResponse) oneResult.get("responseRequest");

                if (oneRequestResponse == null || oneRequestResponse.getResponse() == null) {
                    continue;
                }
                
                byte[] oneResponseBytes = oneRequestResponse.getResponse();
                if (oneResponseBytes == null || oneResponseBytes.length == 0) {
                    callbacks.printOutput("返回结果为空: " + oneUrl);
                    continue;
                }
                
                String oneMethod = (String) oneResult.get("method");
                IResponseInfo responseInfo = helpers.analyzeResponse(oneResponseBytes);
                
                
                TableLogModel result = FingerPrintUtils.fingerFilter(
                        callbacks,
                        message.getMessageReference(), 
                        oneUrl, 
                        oneResponseBytes, 
                        oneRequestResponse.getHttpService(), 
                        helpers, 
                        fingerprintRules,
                        fingerPrintTab.isScanEnabled()  
                );
                
                
                if (result == null) {
                    if (!fingerPrintTab.isScanEnabled()) {

                    }
                    continue;
                }
                
                
                if (result.getResult().isEmpty()) {

                    continue;
                }

                
                result.setStatus(Integer.parseInt(Short.toString(responseInfo.getStatusCode())));
                
                result.setContentType(responseInfo.getStatedMimeType());
                result.setMethod(oneMethod);

                
                
                if (!result.getResult().isEmpty()) {

                    result.setHttpRequestResponse(oneRequestResponse);
                    fingerPrintTab.addLogEntry(result);
                    
                    fingerPrintTab.updateSuccessCount(successCount.incrementAndGet());
                    callbacks.printOutput("[+] 识别到指纹: " + oneUrl + " -> " + result.getResult());
                }
            }
        }
        

    }
    
    private boolean isStaticFile(String url) {
        for (String ext : STATIC_FILE_EXT) {
            if (ext.equalsIgnoreCase(Utils.getUriExt(url))) {
                return true;
            }
        }
        return false;
    }
    
    private boolean isExtractableUrl(String url) {
        for (String ext : STATIC_URL_EXT) {
            if (ext.equalsIgnoreCase(Utils.getUriExt(url))) {
                return true;
            }
        }
        return false;
    }
    
    public void shutdown() {
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdownNow();

        }
    }
    
    
    public void setAcceptingNewTasks(boolean accepting) {
        this.acceptingNewTasks = accepting;
        callbacks.printOutput("[+] 指纹扫描器" + (accepting ? "开始" : "停止") + "接受新任务");
        
        
        if (!accepting && executorService != null) {
            
            int queueSize = executorService.getQueue().size();
            if (queueSize > 0) {

                executorService.getQueue().clear();
            }
        }
    }
    
    /**
     * 更新指纹规则
     * @param newRules 新的规则列表
     */
    public void updateRules(List<FingerPrintRule> newRules) {
        if (newRules == null) {
            callbacks.printError("[!] 更新规则失败: 规则列表为空");
            return;
        }
        
        synchronized (scanLock) {
            this.fingerprintRules = new ArrayList<>(newRules);

        }
    }
}