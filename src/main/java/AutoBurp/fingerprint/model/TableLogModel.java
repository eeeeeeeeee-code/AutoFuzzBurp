package AutoBurp.fingerprint.model;

import burp.IHttpRequestResponse;
import burp.IHttpService;

public class TableLogModel {
    private int id;
    private String url;
    private String method;
    private int status;
    private String title;
    private String result;
    private String type;
    private boolean isImportant;
    private String resultInfo;

    private String matchPattern;  
    private final IHttpService httpService;
    private int requestResponseIndex;
    private String time;
    
    private String contentType;
    
    public TableLogModel(int id, String url, String method, String title, String result, String type,
                         String resultInfo, boolean isImportant, IHttpService httpService,
                         int requestResponseIndex, String currentTime) {
        this.id = id;
        this.url = url;
        this.method = method;
        this.title = title;
        this.result = result;
        this.type = type;
        this.resultInfo = resultInfo;
        this.isImportant = isImportant;
        this.time = currentTime;
        this.httpService = httpService;
        this.requestResponseIndex = requestResponseIndex;
        this.contentType = ""; 
        this.matchPattern = ""; 
    }
    
    
    public int getId() {
        return id;
    }
    
    
    public void setId(int id) {
        this.id = id;
    }

    public String getUrl() {
        return url;
    }

    public int getStatus() {
        return status;
    }
    
    public void setStatus(int status) {
        this.status = status;
    }
    
    public String getTitle() {
        return title;
    }
    
    public void setTitle(String title) {
        this.title = title;
    }
    
    public String getMethod() {
        return method;
    }
    
    public void setMethod(String method) {
        this.method = method;
    }
    
    public String getResult() {
        return result;
    }
    
    public void setResult(String result) {
        this.result = result;
    }
    
    public String getType() {
        return type;
    }
    
    public void setType(String type) {
        this.type = type;
    }
    
    public boolean getIsImportant() {
        return isImportant;
    }
    
    public void setIsImportant(boolean important) {
        isImportant = important;
    }
    
    public String getTime() {
        return time;
    }

    public int getRequestResponseIndex() {
        return requestResponseIndex;
    }

    public String getResultInfo() {
        return resultInfo;
    }
    
    public String getMatchPattern() {
        return matchPattern;
    }

    public void setMatchPattern(String matchPattern) {
        this.matchPattern = matchPattern;
    }

    public void setResultInfo(String resultInfo) {
        this.resultInfo = resultInfo;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }
    
    
    private IHttpRequestResponse httpRequestResponse;
    
    @Override
    public String toString() {
        return "TableLogModel{" +
                "id=" + id +
                ", url='" + url + '\'' +
                ", status=" + status +
                ", title='" + title + '\'' +
                ", method='" + method + '\'' +
                ", result='" + result + '\'' +
                ", type='" + type + '\'' +
                ", isImportant=" + isImportant +
                ", time='" + time + '\'' +
                ", requestResponseIndex=" + requestResponseIndex +
                ", resultInfo='" + resultInfo + '\'' +
                ", contentType='" + contentType + '\'' +
                ", matchPattern='" + matchPattern + '\'' +
                '}';
    }
    
    
    public IHttpRequestResponse getHttpRequestResponse() {
        return httpRequestResponse;
    }
    
    public void setHttpRequestResponse(IHttpRequestResponse httpRequestResponse) {
        this.httpRequestResponse = httpRequestResponse;
    }
}