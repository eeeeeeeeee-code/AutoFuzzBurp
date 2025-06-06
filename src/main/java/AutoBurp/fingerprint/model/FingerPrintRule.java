package AutoBurp.fingerprint.model;

import java.util.List;

public class FingerPrintRule {
    private String cms;
    private String method;
    private String location;
    private List<String> keyword;
    private boolean isImportant;
    private String type;

    public FingerPrintRule() {
    }

    public FingerPrintRule(String type, boolean isImportant, String cms, String method, String location, List<String> keyword) {
        this.cms = cms;
        this.method = method;
        this.location = location;
        this.keyword = keyword;
        this.type = type;
        this.isImportant = isImportant;
    }

    public String getType() {
        return type;
    }


    public boolean getIsImportant() {
        return isImportant;
    }


    public String getCms() {
        return cms;
    }

    public String getMethod() {
        return method;
    }

    public String getLocation() {
        return location;
    }


    public List<String> getKeyword() {
        return keyword;
    }

    public String getInfo() {
        return "cms: " + cms + "\r\nmethod: " + method + "\r\nlocation: " + location + "\r\nkeyword: " + keyword.toString();
    }

}