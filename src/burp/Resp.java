package burp;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

class Resp implements IHttpRequestResponse {
    private IHttpRequestResponse req;
    private HttpRequestResponse montoyaReq;
    private IResponseInfo info;
    private IResponseVariations attributes;

    public long getTimestamp() {
        return timestamp;
    }

    private long timestamp = 0;

    public long getResponseTime() {
        return responseTime;
    }

    private long responseTime = 0;

    public short getStatus() {
        return status;
    }

    private short status = 0;
    private boolean timedOut = false;
    private boolean failed = false;
    private boolean early = false;

    private boolean first = true;



    Resp(IHttpRequestResponse req) {
        this(req, System.currentTimeMillis());
    }

    // converts Montoya HttpRequestResponse to IHttpRequestResponse
    Resp(HttpRequestResponse req) {
        this(new Req(req), System.currentTimeMillis());
    }

    Resp(IHttpRequestResponse req, long startTime) {
        this(req, startTime,  System.currentTimeMillis());
    }

    Resp(IHttpRequestResponse req, long startTime, long endTime) {
        this(req, startTime, endTime, true);
    }

    Resp(IHttpRequestResponse req, long startTime, long endTime, boolean first) {
        this.req = req;
        this.first = first;

        byte[] fail = Utilities.helpers.stringToBytes("null");
        byte[] earlyResponse = Utilities.helpers.stringToBytes("early-response");
        // fixme will interact badly with distribute-damage
        int scanTimeout = Utilities.globalSettings.getInt("timeout") * 1000;

        early = Arrays.equals(req.getResponse(), earlyResponse);
        failed = req.getResponse() == null || req.getResponse().length == 0 || Arrays.equals(req.getResponse(), fail) || early;
        responseTime = endTime - startTime;
//        if (responseTime > 50) {
//            Utilities.out(new String(req.getRequest()));
//            throw new RuntimeException("mmm");
//        }

        // fixme responseTime is wrong when using TurboHelper
        if (responseTime > scanTimeout) {
            this.timedOut = true;
        }

        this.status = Utilities.getCode(req.getResponse());

        timestamp = System.currentTimeMillis();
    }

    IHttpRequestResponse getReq() {
        return req;
    }

    IResponseInfo getInfo() {
        if (info == null) {
            info = Utilities.helpers.analyzeResponse(req.getResponse());
        }
        return info;
    }

    IResponseVariations getAttributes() {
        if (attributes == null) {
            attributes = Utilities.helpers.analyzeResponseVariations(req.getResponse());
        }
        return attributes;
    }

    long getAttribute(String attribute) {
        switch(attribute) {
            case "time":
                return responseTime;
            case "first":
                return first? 1: 0;
            case "failed":
                return failed? 1: 0;
            case "timedout":
                return timedOut? 1: 0;
        }

        try {
            return getAttributes().getAttributeValue(attribute, 0);
        } catch (IllegalArgumentException e) {
            Utilities.out("Invalid attribute: "+attribute);
            Utilities.out("Supported attributes: "+getAttributes().getInvariantAttributes() + getAttributes().getVariantAttributes());
            throw new RuntimeException("Invalid attribute: "+attribute);
        }
    }


    boolean early() {
        return early;
    }

    boolean failed() {
        return failed || timedOut;
    }

    boolean timedOut() {
        return timedOut;
    }

    @Override
    public byte[] getRequest() {
        return req.getRequest();
    }

    @Override
    public void setRequest(byte[] bytes) {
        req.setRequest(bytes);
    }

    @Override
    public byte[] getResponse() {
        return req.getResponse();
    }

    @Override
    public void setResponse(byte[] bytes) {
        req.setResponse(bytes);
    }

    @Override
    public String getComment() {
        return req.getComment();
    }

    @Override
    public void setComment(String s) {
        req.setComment(s);
    }

    @Override
    public String getHighlight() {
        return req.getHighlight();
    }

    @Override
    public void setHighlight(String s) {
        req.setHighlight(s);
    }

    @Override
    public IHttpService getHttpService() {
        return req.getHttpService();
    }

    @Override
    public void setHttpService(IHttpService iHttpService) {
        req.setHttpService(iHttpService);
    }

//    @Override
//    public HttpRequest request() {
//        return montoyaReq.request();
//    }
//
//    @Override
//    public HttpResponse response() {
//        return montoyaReq.response();
//    }
//
//    @Override
//    public Annotations annotations() {
//        return montoyaReq.annotations();
//    }
//
//    @Override
//    public Optional<TimingData> timingData() {
//        return montoyaReq.timingData();
//    }
//
//    @Override
//    public String url() {
//        return montoyaReq.url();
//    }
//
//    @Override
//    public HttpService httpService() {
//        return montoyaReq.httpService();
//    }
//
//    @Override
//    public ContentType contentType() {
//        return montoyaReq.contentType();
//    }
//
//    @Override
//    public short statusCode() {
//        return montoyaReq.statusCode();
//    }
//
//    @Override
//    public List<Marker> requestMarkers() {
//        return montoyaReq.requestMarkers();
//    }
//
//    @Override
//    public List<Marker> responseMarkers() {
//        return montoyaReq.responseMarkers();
//    }
//
//    @Override
//    public HttpRequestResponse copyToTempFile() {
//        return montoyaReq.copyToTempFile();
//    }
//
//    @Override
//    public HttpRequestResponse withAnnotations(Annotations annotations) {
//        return montoyaReq.withAnnotations(annotations);
//    }
//
//    @Override
//    public HttpRequestResponse withRequestMarkers(List<Marker> requestMarkers) {
//        return montoyaReq.withRequestMarkers(requestMarkers);
//    }
//
//    @Override
//    public HttpRequestResponse withRequestMarkers(Marker... requestMarkers) {
//        return montoyaReq.withRequestMarkers(requestMarkers);
//    }
//
//    @Override
//    public HttpRequestResponse withResponseMarkers(List<Marker> responseMarkers) {
//        return montoyaReq.withResponseMarkers(responseMarkers);
//    }
//
//    @Override
//    public HttpRequestResponse withResponseMarkers(Marker... responseMarkers) {
//        return montoyaReq.withResponseMarkers(responseMarkers);
//    }
}
