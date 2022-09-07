package burp;

import java.util.Arrays;

class Resp implements IHttpRequestResponse {
    private IHttpRequestResponse req;
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

    Resp(IHttpRequestResponse req) {
        this(req, System.currentTimeMillis());
    }

    Resp(IHttpRequestResponse req, long startTime) {
        this.req = req;

        byte[] fail = Utilities.helpers.stringToBytes("null");
        byte[] earlyResponse = Utilities.helpers.stringToBytes("early-response");
        // fixme will interact badly with distribute-damage
        int burpTimeout = Integer.parseInt(Utilities.getSetting("project_options.connections.timeouts.normal_timeout"));
        int scanTimeout = Utilities.globalSettings.getInt("timeout") * 1000;

        early = Arrays.equals(req.getResponse(), earlyResponse);
        failed = req.getResponse() == null || req.getResponse().length == 0 || Arrays.equals(req.getResponse(), fail) || early;

        responseTime = System.currentTimeMillis() - startTime;
        if (burpTimeout == scanTimeout) {
            if (failed && responseTime > scanTimeout) {
                this.timedOut = true;
            }
        } else {
            if (responseTime > scanTimeout) {
                this.timedOut = true;
                if (failed) {
                    Utilities.out("TImeout with response. Start time: " + startTime + " Current time: " + System.currentTimeMillis() + " Difference: " + (System.currentTimeMillis() - startTime) + " Tolerance: " + scanTimeout);
                }
            }
        }
        if (!this.failed) {
            this.info = Utilities.helpers.analyzeResponse(req.getResponse());
            this.attributes = Utilities.helpers.analyzeResponseVariations(req.getResponse());
            this.status = this.info.getStatusCode();
        }
        timestamp = System.currentTimeMillis();
    }

    IHttpRequestResponse getReq() {
        return req;
    }

    IResponseInfo getInfo() {
        return info;
    }

    IResponseVariations getAttributes() {
        return attributes;
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
}
