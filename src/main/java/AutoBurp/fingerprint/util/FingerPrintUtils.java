package AutoBurp.fingerprint.util;

import AutoBurp.fingerprint.model.FingerPrintRule;
import AutoBurp.fingerprint.model.TableLogModel;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpService;
import burp.IResponseInfo;

import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class FingerPrintUtils {


    public static TableLogModel fingerFilter(IBurpExtenderCallbacks callbacks, int pid, String oneUrl, byte[] oneResponseBytes,
                                            IHttpService iHttpService, IExtensionHelpers helpers,
                                            List<FingerPrintRule> fingerprintRules, boolean isScanEnabled) {
        if (!isScanEnabled) {
            return null;
        }


        
        TableLogModel logModel = new TableLogModel(pid, oneUrl, "", "", "", "", "", false,
                iHttpService, pid, new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()));

        IResponseInfo responseInfo = helpers.analyzeResponse(oneResponseBytes);
        
        String responseBody = new String(oneResponseBytes, StandardCharsets.UTF_8);
        
        String responseHeaders = responseInfo.getHeaders().toString();
        
        String responseTitle = Utils.getTitle(responseBody);
        
        String mimeType = responseInfo.getStatedMimeType().toLowerCase();
        
        if (responseTitle.isEmpty()) {
            responseTitle = responseBody;
        }
        String finalResponseTitle = responseTitle;

        String faviconHash = "0";

        if (finalResponseTitle.equals(responseBody)) {
            logModel.setTitle("-");
        } else {
            logModel.setTitle(finalResponseTitle);
        }
        
        
        if (mimeType.contains("png") || mimeType.contains("jpeg") || mimeType.contains("icon") || 
            mimeType.contains("image") || oneUrl.contains("favicon.") || oneUrl.contains(".ico")) {
            byte[] body = Arrays.copyOfRange(oneResponseBytes, responseInfo.getBodyOffset(), oneResponseBytes.length);
            faviconHash = Utils.getFaviconHash(body);
            


        }


        
        for (FingerPrintRule rule : fingerprintRules) {
            String locationContent = "";
            String matchLocation = "";

            if ("faviconhash".equals(rule.getMethod())) {
                locationContent = faviconHash;
                matchLocation = "faviconhash";
            } else if ("body".equals(rule.getLocation())) {
                locationContent = responseBody;
                matchLocation = "body";
            } else if ("header".equals(rule.getLocation())) {
                locationContent = responseHeaders;
                matchLocation = "header";
            } else if ("title".equals(rule.getLocation())) {
                locationContent = finalResponseTitle;
                matchLocation = "title";
            } else {
                continue;
            }
            
            boolean allKeywordsPresent = true;
            StringBuilder matchPatternBuilder;

            
            if ("faviconhash".equals(rule.getMethod())) {
                matchPatternBuilder = new StringBuilder("faviconhash").append(": ");
                try {
                    if (!rule.getKeyword().isEmpty() && !faviconHash.equals(rule.getKeyword().get(0))) {
                        allKeywordsPresent = false;
                    } else if (!rule.getKeyword().isEmpty()) {
                        matchPatternBuilder.append(rule.getKeyword().get(0));
                    }
                } catch (Exception e) {
                    allKeywordsPresent = false;
                }
            } else {
                matchPatternBuilder = new StringBuilder(matchLocation).append(": ");
                
                for (int i = 0; i < rule.getKeyword().size(); i++) {
                    String keyword = rule.getKeyword().get(i);
                    if (!locationContent.contains(keyword)) {
                        allKeywordsPresent = false;
                        break;
                    }
                    
                    matchPatternBuilder.append(keyword);
                    if (i < rule.getKeyword().size() - 1) {
                        matchPatternBuilder.append(", ");
                    }
                }
            }

            if (allKeywordsPresent) {
                if (!logModel.getResult().isEmpty()) {
                    
                    if (!logModel.getResult().contains(rule.getCms())) {
                        logModel.setResult(logModel.getResult() + ", " + rule.getCms());
                        
                        
                        if (logModel.getMatchPattern() != null && !logModel.getMatchPattern().isEmpty()) {
                            logModel.setMatchPattern(logModel.getMatchPattern() + " | " + matchPatternBuilder.toString());
                        } else {
                            logModel.setMatchPattern(matchPatternBuilder.toString());
                        }
                    }
                } else {
                    
                    logModel.setResult(rule.getCms());
                    logModel.setMatchPattern(matchPatternBuilder.toString());
                }
                
                
                logModel.setType(rule.getType());
                logModel.setIsImportant(rule.getIsImportant());
                
                String detailInfo = "Time: " + new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()) + 
                                   "\r\nUrl:" + oneUrl + "\r\n指纹详细信息如下：\r\n" + rule.getInfo();
                
                if (logModel.getResultInfo().isEmpty()) {
                    logModel.setResultInfo(detailInfo);
                } else {
                    logModel.setResultInfo(logModel.getResultInfo() + "\r\n\r\n" + detailInfo);
                }
            }
        }

        return logModel;
    }
}