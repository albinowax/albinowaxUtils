package burp;

import org.apache.commons.lang3.NotImplementedException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

abstract class Scan implements IScannerCheck {
    static ZgrabLoader loader = null;
    String name = "";
    SettingsBox scanSettings;

    Scan(String name) {
        this.name = name;
        BulkScan.scans.add(this);
        scanSettings = new SettingsBox();

        // any-scan settings
        scanSettings.register("thread pool size", 8, "The maximum number of threads created for attacks. This roughly equates to the number of concurrent HTTP requests. Increase this number to make large scale attacks go faster, or decrease it to reduce your system load.");
        scanSettings.register("use key", true, "Avoid scanning similar endpoints by generating a key from each request's hostname and protocol, and skipping subsequent requests with matching keys.");
        scanSettings.register("key method", true, "Include the request method in the key");
        scanSettings.register("key path", false, "Include the request path in the key");
        scanSettings.register("key status", true, "Include the response status code in the key");
        scanSettings.register("key content-type", true, "Include the response content-type in the key");
        scanSettings.register("key server", true, "Include the response Server header in the key");
        scanSettings.register("key input name", true, "Include the name of the parameter being scanned in the key");
        scanSettings.register("key header names", false, "Include all response header names (but not values) in the key");
        scanSettings.register("filter", "", "Only scan requests containing the configured string");
        scanSettings.register("mimetype-filter", "", "Only scan responses with the configured string in their mimetype");
        scanSettings.register("resp-filter", "", "Only scan requests with responses containing the configured string.");
        scanSettings.register("filter HTTP", false, "Only scan HTTPS requests");
        scanSettings.register("timeout", 10, "The time after quick a response is considered to have timed out. Tweak with caution, and be sure to adjust Burp's request timeout to match.");
        scanSettings.register("skip vulnerable hosts", false, "Don't scan hosts already flagged as vulnerable during this scan. Reload the extension to clear flags.");
        scanSettings.register("skip flagged hosts", false, "Don't report issues on hosts already flagged as vulnerable");
        scanSettings.register("flag new domains", false, "Adjust the title of issues reported on hosts that don't have any other issues listed in the sitemap");


        // specific-scan settings TODO remove
        scanSettings.register("confirmations", 5, "The number of repeats used to confirm behaviour is consistent. Increase this to reduce false positives caused by random noise");
        scanSettings.register("report tentative", true, "Report less reliable isssues (only relevant to Backslash Powered Scanner?)");
        scanSettings.register("include origin in cachebusters", true);
        scanSettings.register("include path in cachebusters", false);

        //Utilities.callbacks.registerScannerCheck(this);
    }

    List<String> getSettings() {
//        Set<String> settings = new HashSet<>();
//        settings.addAll(scanSettings.getSettings());
//        settings.addAll(BulkScanLauncher.genericSettings.getSettings());
//        return new ArrayList<>(settings);
        return scanSettings.getSettings();
    }

    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        throw new RuntimeException("doScan(byte[] baseReq, IHttpService service) invoked but not implemented on class "+this.name);
    }

    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse) {
        return doScan(baseRequestResponse.getRequest(), baseRequestResponse.getHttpService());
    }

    boolean shouldScan(IHttpRequestResponse baseRequestResponse) {
        if (Utilities.globalSettings.getBoolean("skip vulnerable hosts") && BulkScan.hostsToSkip.containsKey(baseRequestResponse.getHttpService().getHost())) {
            return false;
        }
        return true;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return doScan(baseRequestResponse.getRequest(), baseRequestResponse.getHttpService());
    }

    void setRequestMethod(ZgrabLoader loader) {
        this.loader = loader;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    static void recordCandidateFound() {
        BulkScanLauncher.getTaskEngine().candidates.incrementAndGet();
    }

    static void report(String title, String detail, Resp... requests) {
        report(title, detail, null, requests);
    }


    static void report(String title, String detail, byte[] baseBytes, Resp... requests) {
        IHttpRequestResponse base = requests[0].getReq();
        IHttpService service = base.getHttpService();

        ArrayList<IHttpRequestResponse> reqsToReport = new ArrayList<>();

        if (Utilities.globalSettings.getBoolean("skip flagged hosts") && BulkScan.domainAlreadyFlagged(service)) {
            return;
        }

        if (Utilities.globalSettings.getBoolean("flag new domains")) {
            if (!BulkScan.domainAlreadyFlagged(service)) {
                title = "NEW| " + title;
            }
        }

        if (baseBytes != null) {
            Resp baseReq = new Resp(new Req(baseBytes, null, service));
            reqsToReport.add(baseReq.getReq());
        }

        for (Resp request : requests) {
            reqsToReport.add(request.getReq());
        }

        if (Utilities.isBurpPro()) {
            Utilities.callbacks.addScanIssue(new CustomScanIssue(service, Utilities.getURL(base.getRequest(), service), reqsToReport.toArray(new IHttpRequestResponse[0]), title, detail, "High", "Tentative", "."));
        } else {
            StringBuilder serialisedIssue = new StringBuilder();
            serialisedIssue.append("Found issue: ");
            serialisedIssue.append(title);
            serialisedIssue.append("\n");
            serialisedIssue.append("Target: ");
            serialisedIssue.append(service.getProtocol());
            serialisedIssue.append("://");
            serialisedIssue.append(service.getHost());
            serialisedIssue.append("\n");
            serialisedIssue.append(detail);
            serialisedIssue.append("\n");
            serialisedIssue.append("Evidence: \n======================================\n");
            for (IHttpRequestResponse req : reqsToReport) {
                serialisedIssue.append(Utilities.helpers.bytesToString(req.getRequest()));
//                serialisedIssue.append("\n--------------------------------------\n");
//                if (req.getResponse() == null) {
//                    serialisedIssue.append("[no response]");
//                }
//                else {
//                    serialisedIssue.append(Utilities.helpers.bytesToString(req.getResponse()));
//                }
                serialisedIssue.append("\n======================================\n");
            }

            Utilities.out(serialisedIssue.toString());
        }
    }

    static Resp request(IHttpService service, byte[] req) {
        return request(service, req, 0);
    }

    static Resp request(IHttpService service, byte[] req, int maxRetries) {
        return request(service, req, maxRetries, false);
    }

    static Resp request(IHttpService service, byte[] req, int maxRetries, boolean forceHTTP1) {
        return request(service, req, maxRetries, forceHTTP1, null);
    }

    static Resp request(IHttpService service, byte[] req, int maxRetries, boolean forceHTTP1, HashMap<String, Boolean> config) {
        if (Utilities.unloaded.get()) {
            throw new RuntimeException("Aborting due to extension unload");
        }

        IHttpRequestResponse resp = null;
        Utilities.requestCount.incrementAndGet();
        long startTime = System.currentTimeMillis();
        if (false && config != null && config.get("nest-requests")) {

            // should I use Turbo/h1, or H/2?
            // ... I guess H/1
        } else if (loader == null) {
            int attempts = 0;
            while ((resp == null || resp.getResponse() == null) && attempts <= maxRetries) {
                startTime = System.currentTimeMillis();
                try {
                    byte[] responseBytes;
                    if (forceHTTP1 || !Utilities.supportsHTTP2) {
                        req = Utilities.replaceFirst(req, "HTTP/2\r\n", "HTTP/1.1\r\n");
                    }

                    if (Utilities.supportsHTTP2) {
                        //responseBytes = Utilities.callbacks.makeHttpRequest(service, req).getResponse();
                        responseBytes = Utilities.callbacks.makeHttpRequest(service, req, forceHTTP1).getResponse();
                    } else {
                        responseBytes = Utilities.callbacks.makeHttpRequest(service, req).getResponse();
                    }
                    resp = new Req(req, responseBytes, service);
                } catch (NoSuchMethodError e) {
                    Utilities.supportsHTTP2 = false;
                    continue;
                } catch (RuntimeException e) {
                    Utilities.out("Recovering from request exception: " + service.getHost());
                    Utilities.err("Recovering from request exception: " + service.getHost());
                    resp = new Req(req, null, service);
                }
                attempts += 1;
            }
        } else {
            throw new NotImplementedException("hmm");
//            byte[] response = loader.getResponse(service.getHost(), req);
//            if (response == null) {
//                try {
//                    String template = Utilities.helpers.bytesToString(req).replace(service.getHost(), "%d");
//                    String name = Integer.toHexString(template.hashCode());
//                    PrintWriter out = new PrintWriter("/Users/james/PycharmProjects/zscanpipeline/generated-requests/"+name);
//                    out.print(template);
//                    out.close();
//                } catch (FileNotFoundException e) {
//                    e.printStackTrace();
//                }
//
//                Utilities.out("Couldn't find response. Sending via Burp instead");
//                Utilities.out(Utilities.helpers.bytesToString(req));
//                return new Resp(Utilities.callbacks.makeHttpRequest(service, req, forceHTTP1), startTime);
//                //throw new RuntimeException("Couldn't find response");
//            }
//
//            if (Arrays.equals(response, "".getBytes())) {
//                response = null;
//            }
//
//            resp = new Req(req, response, service);
        }

        return new Resp(resp, startTime);
    }
}
