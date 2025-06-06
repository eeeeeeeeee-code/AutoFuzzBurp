package AutoBurp.fuzzer.upload;

import AutoBurp.generator.UploadPayloadGenerator;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UploadFuzzer implements IIntruderPayloadGenerator {
    private final IExtensionHelpers helpers;
    private final IIntruderAttack attack;
    private int payloadIndex = 0;
    private List<String> attackPayloads = new ArrayList<>();
    private boolean initialized = false;

    private final IBurpExtenderCallbacks callbacks;

    public UploadFuzzer(IExtensionHelpers helpers, IIntruderAttack attack, IBurpExtenderCallbacks callbacks) { 
        this.helpers = helpers;
        this.attack = attack;
        this.callbacks = callbacks;
    }

    @Override
    public boolean hasMorePayloads() {
        if (!initialized) {
            return true;
        }

        return payloadIndex < attackPayloads.size();
    }

    @Override
    public byte[] getNextPayload(byte[] baseValue) {
        if (!initialized) {

            initializePayloads(baseValue);
            initialized = true;

        }

        if (payloadIndex >= attackPayloads.size()) {
            return baseValue;
        }

        String payload = attackPayloads.get(payloadIndex);
        payloadIndex++;
        return payload.getBytes();
    }

    private void initializePayloads(byte[] baseValue) {
        String selectedArea = new String(baseValue);
        
        boolean isFullSection = selectedArea.contains("Content-Disposition:") &&
                (selectedArea.contains("filename=") || selectedArea.contains("filename=\"")) &&
                selectedArea.contains("Content-Type:");
        

        
        if (isFullSection) {
            Matcher filenameMatcher = Pattern.compile("filename=\"([^\"]*)\"").matcher(selectedArea);
            Matcher namematcher = Pattern.compile("name=\"([^\"]*)\"").matcher(selectedArea);
            Matcher contentTypeMatcher = Pattern.compile("Content-Type:\\s*([^\\r\\n]*)").matcher(selectedArea);


            if (filenameMatcher.find() && filenameMatcher.group(1).contains(".")) {
                String originalFilename = filenameMatcher.group(1);
                String originalExt = originalFilename.substring(originalFilename.lastIndexOf('.') + 1);
                String name = namematcher.find() ? namematcher.group(1) : "file";
                String contentType =  contentTypeMatcher.find() ? contentTypeMatcher.group(1).trim() : "image/jpeg";

                List<String> sectionPayloads = UploadPayloadGenerator.getFuzzPayloadsForFullSection(selectedArea);

                
                String template = "Content-Disposition: form-data; name=\""+name+"\"; filename=\"test." + originalExt +
                        "\"\r\nContent-Type:"+contentType;
                List<String> singleElementPayloads = UploadPayloadGenerator.getAttackPayloads(template);

                List<String> convertedPayloads = new ArrayList<>(singleElementPayloads);

                Set<String> uniquePayloads = new HashSet<>();
                uniquePayloads.addAll(sectionPayloads);
                uniquePayloads.addAll(convertedPayloads);
                attackPayloads = new ArrayList<>(uniquePayloads);
            } else {
                attackPayloads = UploadPayloadGenerator.getFuzzPayloadsForFullSection(selectedArea);
            }
        } else {
            attackPayloads = UploadPayloadGenerator.getAttackPayloads(selectedArea);
        }

        
        if (attackPayloads.size() > 1000) {
            attackPayloads = attackPayloads.subList(0, 1000);
        }

        attack.getHttpService().getHost();
    }

    @Override
    public void reset() {
        payloadIndex = 0;
    }
}