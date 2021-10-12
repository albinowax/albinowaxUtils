package burp;

import org.apache.commons.collections4.queue.CircularFifoQueue;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.*;

import static java.lang.Math.min;
import static org.apache.commons.lang3.math.NumberUtils.max;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

class SettingsBox {
    private LinkedHashSet<String> settings;

    public SettingsBox() {
         settings = new LinkedHashSet<>();
    }

    public void register(String name, Object value) {
        settings.add(name);
        Utilities.globalSettings.registerSetting(name, value);
    }

    public boolean contains(String key) {
        return settings.contains(key);
    }

    public void importSettings(SettingsBox newSettings) {
        settings.addAll(newSettings.getSettings());
    }

    public ArrayList<String> getSettings() {
        return new ArrayList<>(settings);
    }
}

class BulkScanLauncher {

    private static ScanPool taskEngine;

    BulkScanLauncher(List<Scan> scans) {
        taskEngine = buildTaskEngine();
        Utilities.callbacks.registerContextMenuFactory(new OfferBulkScan(scans));
    }

    private static ScanPool buildTaskEngine() {
        BlockingQueue<Runnable> tasks;
        tasks = new LinkedBlockingQueue<>();

        Utilities.globalSettings.registerSetting("thread pool size", 8);
        ScanPool taskEngine = new ScanPool(Utilities.globalSettings.getInt("thread pool size"), Utilities.globalSettings.getInt("thread pool size"), 10, TimeUnit.MINUTES, tasks);
        Utilities.globalSettings.registerListener("thread pool size", value -> {
            Utilities.out("Updating active thread pool size to "+value);
            try {
                taskEngine.setCorePoolSize(Integer.parseInt(value));
                taskEngine.setMaximumPoolSize(Integer.parseInt(value));
            } catch (IllegalArgumentException e) {
                taskEngine.setMaximumPoolSize(Integer.parseInt(value));
                taskEngine.setCorePoolSize(Integer.parseInt(value));
            }
        });
        return taskEngine;
    }

    static ScanPool getTaskEngine() {
        return taskEngine;
    }
}

class SortByParentDomain implements  Comparator<ScanItem> {
    @Override
    public int compare(ScanItem o1, ScanItem o2) {
        int dot1 = StringUtils.countMatches(o1.host, ".");
        int dot2 = StringUtils.countMatches(o2.host, ".");
        int score = dot1 - dot2;
        if (score == 0) {
            score = o1.host.length() - o2.host.length();
        }
        return score;
    }
}

class BulkScan implements Runnable  {
    private IHttpRequestResponse[] reqs;
    private Scan scan;
    private ConfigurableSettings config;
    public static List<Scan> scans = new ArrayList<>();
    static ConcurrentHashMap<String, Boolean> hostsToSkip = new ConcurrentHashMap<>();

    BulkScan(Scan scan, IHttpRequestResponse[] reqs, ConfigurableSettings config) {
        this.scan = scan;
        this.reqs = reqs;
        this.config = config;
    }

    public void run() {
        try {
            long start = System.currentTimeMillis();
            ScanPool taskEngine = BulkScanLauncher.getTaskEngine();

            int queueSize = taskEngine.getQueue().size();
            Utilities.log("Adding " + reqs.length + " tasks to queue of " + queueSize);
            queueSize += reqs.length;
            int thread_count = taskEngine.getCorePoolSize();


            //ArrayList<IHttpRequestResponse> reqlist = new ArrayList<>(Arrays.asList(reqs));

            ArrayList<ScanItem> reqlist = new ArrayList<>();

            for (IHttpRequestResponse req : reqs) {
                if (req.getRequest() == null) {
                    Utilities.out("Skipping null request - not sure how that got there");
                    continue;
                }
                reqlist.add(new ScanItem(req, config, scan));
            }

            Collections.shuffle(reqlist);
            Collections.sort(reqlist, new SortByParentDomain());

            int cache_size = queueSize; //thread_count;

            Set<String> keyCache = new HashSet<>();

            Queue<String> cache = new CircularFifoQueue<>(cache_size);
            HashSet<String> remainingHosts = new HashSet<>();

            int i = 0;
            int queued = 0;
            boolean remove;
            int prepared = 0;
            int totalRequests = reqlist.size();
            String filter = Utilities.globalSettings.getString("filter");
            String respFilter = Utilities.globalSettings.getString("resp-filter");
            boolean applyRespFilter = !"".equals(respFilter);
            boolean applyFilter = !"".equals(filter);
            String mimeFilter = Utilities.globalSettings.getString("mimetype-filter");
            boolean applyMimeFilter = !"".equals(mimeFilter);
            boolean applySchemeFilter = config.getBoolean("filter HTTP");

            // every pass adds at least one item from every host
            while (!reqlist.isEmpty()) {
                Utilities.out("Loop " + i++);
                ListIterator<ScanItem> left = reqlist.listIterator();
                while (left.hasNext()) {
                    remove = true;
                    ScanItem req = left.next();

                    if (applySchemeFilter && "http".equals(req.req.getHttpService().getProtocol())) {
                        left.remove();
                        continue;
                    }

                    if (applyFilter && !Utilities.containsBytes(req.req.getRequest(), filter.getBytes())) {
                        left.remove();
                        continue;
                    }

                    if (applyMimeFilter) {
                        byte[] resp = req.req.getResponse();
                        if (resp == null) {
                            if (!Utilities.getHeader(req.req.getRequest(), "Accept").toLowerCase().contains(mimeFilter)) {
                                left.remove();
                                continue;
                            }
                        } else {
                            if (!Utilities.getHeader(req.req.getResponse(), "Content-Type").toLowerCase().contains(mimeFilter)) {
                                left.remove();
                                continue;
                            }
                        }
                    }

                    // fixme doesn't actually work - maybe the resp is always null?
                    if (applyRespFilter) {
                        byte[] resp = req.req.getResponse();
                        if (resp == null || !Utilities.containsBytes(resp, respFilter.getBytes())) {
                            Utilities.log("Skipping request due to response filter");
                            left.remove();
                            continue;
                        }
                    }

                    String host = req.host;
                    if (cache.contains(host)) {
                        remainingHosts.add(host);
                        continue;
                    }


                    if (scan instanceof ParamScan && !req.prepared()) {
                        ArrayList<ScanItem> newItems = req.prepare();
                        //Utilities.log("Prepared " + prepared + " of " + totalRequests);
                        prepared++;
                        left.remove();
                        remove = false;
                        if (newItems.size() == 0) {
                            //Utilities.log("No params in request");
                            continue;
                        }
                        req = newItems.remove(0);
                        for (ScanItem item : newItems) {
                            String key = item.getKey();
                            //Utilities.log("Param Key: "+key);
                            if (!keyCache.contains(key)) {
                                left.add(item);
                            }
                        }
                    }

                    if (config.getBoolean("use key")) {
                        String key = req.getKey();
                        if (keyCache.contains(key)) {
                            if (remove) {
                                left.remove();
                            }
                            continue;
                        }
                        keyCache.add(key);
                    }

                    cache.add(host);
                    if (remove) {
                        left.remove();
                    }
                    Utilities.log("Adding request on " + host + " to queue");
                    queued++;
                    taskEngine.execute(new BulkScanItem(scan, req, start));
                }

                cache = new CircularFifoQueue<>(max(min(remainingHosts.size() - 1, thread_count), 1));
            }

            Utilities.out("Queued " + queued + " attacks from " + totalRequests + " requests in " + (System.currentTimeMillis() - start) / 1000 + " seconds");
        } catch (Exception e) {
            Utilities.out("Queue aborted due to exception");
            Utilities.showError(e);
        }
    }
}

class ScanItem {
    private Scan scan;
    IHttpRequestResponse req;
    String host;
    private ConfigurableSettings config;
    private boolean prepared = false;
    IScannerInsertionPoint insertionPoint;
    private IParameter param;
    private String key = null;
    String method = null;


    ScanItem(IHttpRequestResponse req, ConfigurableSettings config, Scan scan) {
        this.req = req;
        this.host = req.getHttpService().getHost();
        this.config = config;
        this.scan = scan;
    }

    ScanItem(IHttpRequestResponse req, ConfigurableSettings config, Scan scan, IParameter param) {
        this.req = req;
        this.host = req.getHttpService().getHost();
        this.config = config;
        this.param = param;
        insertionPoint = new RawInsertionPoint(req.getRequest(), param.getName(), param.getValueStart(), param.getValueEnd());
        this.prepared = true;
        this.scan = scan;
    }

    boolean prepared() {
        return prepared;
    }

    ArrayList<ScanItem> prepare() {
        ArrayList<ScanItem> items = new ArrayList<>();

        method = Utilities.getMethod(req.getRequest());

// no longer required as the filter is done earlier
//        String filterValue = Utilities.globalSettings.getString("filter");
//        if (!"".equals(filterValue)) {
//            if (req.getResponse() == null || !Utilities.containsBytes(req.getResponse(), filterValue.getBytes())) {
//                return items;
//            }
//        }
        prepared = true;

        // todo we kinda need the base-value
        if (Utilities.containsBytes(req.getResponse(), "HTTP/2".getBytes())) {
            if (Utilities.globalSettings.getBoolean("params: scheme")) {
                byte[] updated = Utilities.addOrReplaceHeader(req.getRequest(), ":scheme", "m838jacxka");
                Req newReq = new Req(updated, req.getResponse(), req.getHttpService());
                items.add(new ScanItem(newReq, config, scan, Utilities.paramify(updated, "scheme-proto", "m838jacxka", "https")));
            }

            if (Utilities.globalSettings.getBoolean("params: scheme-path")) {
                byte[] updated = Utilities.addOrReplaceHeader(req.getRequest(), ":scheme", "https://" + req.getHttpService().getHost() + "/m838jacxka");
                Req newReq = new Req(updated, req.getResponse(), req.getHttpService());
                items.add(new ScanItem(newReq, config, scan, Utilities.paramify(updated, "scheme-path", "m838jacxka", "m838jacxka")));
            }

            if (Utilities.globalSettings.getBoolean("params: scheme-host")) {
                byte[] updated = Utilities.addOrReplaceHeader(req.getRequest(), ":scheme", "https://m838jacxka/");
                Req newReq = new Req(updated, req.getResponse(), req.getHttpService());
                items.add(new ScanItem(newReq, config, scan, Utilities.paramify(updated, "scheme-host", "m838jacxka", "m838jacxka")));
            }
        }


        if (!Utilities.globalSettings.getBoolean("params: query")) {
            return items;
        }

        // don't waste time analysing GET requests with no = in the request line
        // todo check method here once POST params are supported
        if (!Utilities.getPathFromRequest(req.getRequest()).contains("=")) {
            if (!Utilities.globalSettings.getBoolean("params: dummy")) {
                return items;
            }

            // if you use setRequest instead, it will overwrite the original!
            // fixme somehow triggers a stackOverflow
        }

        if (Utilities.globalSettings.getBoolean("params: dummy")) {
            req = new Req(Utilities.appendToQuery(req.getRequest(), Utilities.globalSettings.getString("dummy param name")+"=z"), req.getResponse(), req.getHttpService());
        }

        // analyzeRequest is really slow
        //reqInfo = Utilities.helpers.analyzeRequest(req);
        //ArrayList<IParameter> params = new ArrayList<>(reqInfo.getParameters());
        // fixme why is this null?
        ArrayList<PartialParam> params = Utilities.getParams(req.getRequest());

        // Utilities.globalSettings.getBoolean("param-scan cookies")
        for (IParameter param: params) {
            if (param.getType() != IParameter.PARAM_URL) {
                continue;
            }
            items.add(new ScanItem(req, config, scan, param));
        }
        return items;
    }

    String getKey() {

        if (method == null) {
            method = Utilities.getMethod(req.getRequest());
        }

        if (key != null) {
            return key;
        }

        StringBuilder key = new StringBuilder();
        if (!config.getBoolean("filter HTTP")) {
            key.append(req.getHttpService().getProtocol());
        }

        key.append(req.getHttpService().getHost());

        if (scan instanceof ParamScan) {
            key.append(param.getName());
            key.append(param.getType());
        }

        if(config.getBoolean("key method")) {
            key.append(method);
        }

        if (req.getResponse() == null && config.getBoolean("key content-type")) {
            key.append(Utilities.getExtension(req.getRequest()));
        }

        if (req.getResponse() != null && (config.getBoolean("key header names") || config.getBoolean("key status") || config.getBoolean("key content-type") || config.getBoolean("key server"))) {
            IResponseInfo respInfo = Utilities.helpers.analyzeResponse(req.getResponse());

            if (config.getBoolean("key header names")) {
                StringBuilder headerNames = new StringBuilder();
                for (String header : respInfo.getHeaders()) {
                    headerNames.append(header.split(": ")[0]);
                }
                key.append(headerNames.toString());
            }

            if (config.getBoolean("key status")) {
                key.append(respInfo.getStatusCode());
            }

            if (config.getBoolean("key content-type")) {
                key.append(respInfo.getStatedMimeType());
            }

            if (config.getBoolean("key server")) {
                key.append(Utilities.getHeader(req.getResponse(), "Server"));
            }
        }

        this.key = key.toString();

        return this.key;
    }

}

class TriggerBulkScan implements ActionListener {

    private IHttpRequestResponse[] reqs;
    private IScanIssue[] issues;
    private Scan scan;

    TriggerBulkScan(Scan scan, IHttpRequestResponse[] reqs) {
        this.scan = scan;
        this.reqs = reqs;
    }

    TriggerBulkScan(Scan scan, IScanIssue[] issues) {
        this.scan = scan;
        this.issues = issues;
    }

    public void actionPerformed(ActionEvent e) {
        if (this.reqs == null) {
            this.reqs = new IHttpRequestResponse[issues.length];
            for (int i=0; i<issues.length; i++) {
                IScanIssue issue = issues[i];
                reqs[i] = issue.getHttpMessages()[0];
                //reqs[i] = new Req(Utilities.helpers.buildHttpRequest(issue.getUrl()), null, issue.getHttpService());
            }
        }

        ConfigurableSettings config = Utilities.globalSettings.showSettings(scan.scanSettings.getSettings());
        if (config != null) {
            BulkScan bulkScan = new BulkScan(scan, reqs, config);
            (new Thread(bulkScan)).start();
        }
    }
}

class OfferBulkScan implements IContextMenuFactory {
    private List<Scan> scans;

    OfferBulkScan(List<Scan> scans) {
        this.scans = scans;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] reqs = invocation.getSelectedMessages();
        List<JMenuItem> options = new ArrayList<>();

        JMenu scanMenu = new JMenu(Utilities.name);

        if (reqs != null && reqs.length > 0) {
            for (Scan scan : scans) {
                JMenuItem probeButton = new JMenuItem(scan.name);
                probeButton.addActionListener(new TriggerBulkScan(scan, reqs));
                scanMenu.add(probeButton);
            }
        } else if (invocation.getSelectedIssues().length > 0) {
            for (Scan scan : scans) {
                JMenuItem probeButton = new JMenuItem(scan.name);
                probeButton.addActionListener(new TriggerBulkScan(scan, invocation.getSelectedIssues()));
                scanMenu.add(probeButton);
            }
        }

        options.add(scanMenu);
        return options;
    }
}

class BulkScanItem implements Runnable {

    private final ScanItem baseItem;
    private final IHttpRequestResponsePersisted baseReq;
    private final Scan scanner;
    private final long start;

    BulkScanItem(Scan scanner, ScanItem baseReq, long start) {
        this.baseReq = Utilities.callbacks.saveBuffersToTempFiles(baseReq.req);
        this.baseItem = baseReq;
        this.scanner = scanner;
        this.start = start;
    }

    public void run() {
        try {
            if (scanner.shouldScan(baseReq)) {
                if (scanner instanceof ParamScan) {
                    scanner.doActiveScan(baseReq, baseItem.insertionPoint);
                } else {
                    scanner.doScan(baseReq);
                }
            } else {
                Utilities.out("Skipping already-confirmed-vulnerable host: "+baseItem.host);
            }
            ScanPool engine = BulkScanLauncher.getTaskEngine();
            long done = engine.getCompletedTaskCount() + 1;
            Utilities.out("Completed "+baseItem.host + ": " + done + " of " + (engine.getQueue().size() + done) + " in " + (System.currentTimeMillis() - start) / 1000 + " seconds with " + Utilities.requestCount.get() + " requests, " + engine.candidates + " candidates and " + engine.findings + " findings ");
        } catch (Exception e) {
            Utilities.showError(e);
        }
    }
}


abstract class ParamScan extends Scan {
    public ParamScan(String name) {
        super(name);
        // param-scan settings
        scanSettings.register("params: dummy", false);
        //genericSettings.register("params: cookies", false);
        //genericSettings.register("special params", false);
        scanSettings.register("dummy param name", "utm_campaign");
        scanSettings.register("params: query", true);
        scanSettings.register("params: scheme", false);
        scanSettings.register("params: scheme-host", false);
        scanSettings.register("params: scheme-path", false);
    }

    abstract List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint);

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // todo convert insertion point into appropriate format
        return doScan(baseRequestResponse, insertionPoint);
    }

}

abstract class Scan implements IScannerCheck {
    static ZgrabLoader loader = null;
    String name = "";
    SettingsBox scanSettings;

    Scan(String name) {
        this.name = name;
        BulkScan.scans.add(this);
        scanSettings = new SettingsBox();

        // any-scan settings
        scanSettings.register("thread pool size", 8);
        scanSettings.register("use key", true);
        scanSettings.register("key method", true);
        scanSettings.register("key status", true);
        scanSettings.register("key content-type", true);
        scanSettings.register("key server", true);
        scanSettings.register("key header names", false);
        scanSettings.register("filter", "");
        scanSettings.register("mimetype-filter", "");
        scanSettings.register("resp-filter", "");
        scanSettings.register("filter HTTP", false);
        scanSettings.register("timeout", 10);
        scanSettings.register("skip vulnerable hosts", false);
        scanSettings.register("flag new domains", false);

        // specific-scan settings TODO remove
        scanSettings.register("confirmations", 5);
        scanSettings.register("report tentative", true);
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
        throw new RuntimeException("doScan(byte[] baseReq, IHttpService service) invoked but not implemented");
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

        if (Utilities.globalSettings.getBoolean("flag new domains")) {
            if (Utilities.callbacks.getScanIssues(service.getProtocol()+"://"+service.getHost()).length == 0) {
                title = "NEW| "+title;
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
            for (IHttpRequestResponse req: reqsToReport) {
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
        if (Utilities.unloaded.get()) {
            throw new RuntimeException("Aborting due to extension unload");
        }

        IHttpRequestResponse resp = null;
        Utilities.requestCount.incrementAndGet();
        long startTime = System.currentTimeMillis();
        if (loader == null) {
            int attempts = 0;
            while (( resp == null || resp.getResponse() == null) && attempts <= maxRetries) {
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
                } catch (java.lang.RuntimeException e) {
                    Utilities.out("Recovering from request exception: "+service.getHost());
                    Utilities.err("Recovering from request exception: "+service.getHost());
                    resp = new Req(req, null, service);
                }
                attempts += 1;
            }
        }
        else {
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

class ScanPool extends ThreadPoolExecutor implements IExtensionStateListener {

    AtomicInteger candidates = new AtomicInteger(0);
    AtomicInteger findings = new AtomicInteger(0);

    ScanPool(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, BlockingQueue<Runnable> workQueue) {
        super(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue);
        Utilities.callbacks.registerExtensionStateListener(this);
    }

    @Override
    public void extensionUnloaded() {
        getQueue().clear();
        shutdown();
    }
}

class Resp {
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

    boolean early() { return early;}

    boolean failed() {
        return failed;
    }

    boolean timedOut() {
        return timedOut;
    }
}

class Req implements IHttpRequestResponse {

    private byte[] req;
    private byte[] resp;
    private IHttpService service;

    Req(byte[] req, byte[] resp, IHttpService service) {
        this.req = req;
        this.resp = resp;
        this.service = service;
    }

    @Override
    public byte[] getRequest() {
        return req;
    }

    @Override
    public void setRequest(byte[] message) {
        this.req = message;
    }

    @Override
    public byte[] getResponse() {
        return resp;
    }

    @Override
    public void setResponse(byte[] message) {
        this.resp = message;
    }

    @Override
    public String getComment() {
        return null;
    }

    @Override
    public void setComment(String comment) {

    }

    @Override
    public String getHighlight() {
        return null;
    }

    @Override
    public void setHighlight(String color) {

    }

    @Override
    public IHttpService getHttpService() {
        return service;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.service = httpService;
    }

//    @Override
//    public String getHost() {
//        return service.getHost();
//    }
//
//    @Override
//    public int getPort() {
//        return service.getPort();
//    }
//
//    @Override
//    public String getProtocol() {
//        return service.getProtocol();
//    }
//
//    @Override
//    public void setHost(String s) {
//
//    }
//
//    @Override
//    public void setPort(int i) {
//
//    }
//
//    @Override
//    public void setProtocol(String s) {
//
//    }
//
//    @Override
//    public URL getUrl() {
//        return Utilities.getURL(req, service);
//    }
//
//    @Override
//    public short getStatusCode() {
//        return 0;
//    }
}

class RawInsertionPoint implements IScannerInsertionPoint {
    private byte[] prefix;
    private byte[] suffix;
    private String baseValue;
    private String name;

    RawInsertionPoint(byte[] req, String name, int start, int end) {
        this.name = name;
        this.prefix = Arrays.copyOfRange(req, 0, start);
        this.suffix = Arrays.copyOfRange(req, end, req.length);
        baseValue = new String(Arrays.copyOfRange(req, start, end));
    }


    @Override
    public String getInsertionPointName() {
        return name;
    }

    @Override
    public String getBaseValue() {
        return baseValue;
    }

    @Override
    public byte[] buildRequest(byte[] payload) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(prefix);
            outputStream.write(payload);
            outputStream.write(suffix);
        } catch (IOException e) {

        }

        return Utilities.fixContentLength(outputStream.toByteArray());
    }

    @Override
    public int[] getPayloadOffsets(byte[] payload) {
        return new int[]{prefix.length, prefix.length+payload.length};
    }

    @Override
    public byte getInsertionPointType() {
        return IScannerInsertionPoint.INS_EXTENSION_PROVIDED;
    }
}

class CustomScanIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;
    private String remediation;

    CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity,
            String confidence,
            String remediation) {
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.confidence = confidence;
        this.remediation = remediation;
    }

    CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse httpMessages,
            String name,
            String detail,
            String severity,
            String confidence,
            String remediation) {
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = new IHttpRequestResponse[1];
        this.httpMessages[0] = httpMessages;

        this.confidence = confidence;
        this.remediation = remediation;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return remediation;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    public String getHost() {
        return null;
    }

    public int getPort() {
        return 0;
    }

    public String getProtocol() {
        return null;
    }
}
