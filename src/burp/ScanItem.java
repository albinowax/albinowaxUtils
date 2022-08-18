package burp;

import java.util.ArrayList;

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

    ScanItem(IHttpRequestResponse req, ConfigurableSettings config, Scan scan, IParameter param, IScannerInsertionPoint insertionPoint) {
        this.req = req;
        this.config = config;
        this.scan = scan;
        this.insertionPoint = insertionPoint;
        this.host = req.getHttpService().getHost();
        this.prepared = true;
        this.param = param;
    }

    ScanItem(IHttpRequestResponse req, ConfigurableSettings config, Scan scan, IParameter param) {
        this.req = req;
        this.host = req.getHttpService().getHost();
        this.config = config;
        this.param = param;
        insertionPoint = new RawInsertionPoint(req.getRequest(), param.getName(), param.getValueStart(), param.getValueEnd(), param.getType());
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

        // fixme analyzeRequest is really slow, should implement this stuff myself
        boolean cookiesToScan = Utilities.globalSettings.getBoolean("params: cookie") && !"".equals(Utilities.getHeader(req.getRequest(), "Cookie"));
        boolean bodyToScan = Utilities.globalSettings.getBoolean("params: body") && !"".equals(Utilities.getBody(req.getRequest()));
        if (cookiesToScan || bodyToScan) {
            ArrayList<IParameter> fancyParams = new ArrayList<>(Utilities.helpers.analyzeRequest(req).getParameters());
            for (IParameter param : fancyParams) {
                byte type = param.getType();
                switch (type) {
                    case IParameter.PARAM_COOKIE:
                        if (cookiesToScan) {
                            break;
                        }
                        continue;
                    case IParameter.PARAM_BODY:
                        if (bodyToScan) {
                            break;
                        }
                    default:
                        continue;
                }
                IScannerInsertionPoint insertionPoint = new ParamInsertionPoint(req.getRequest(), param);
                items.add(new ScanItem(req, config, scan, param, insertionPoint));
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
            req = new Req(Utilities.appendToQuery(req.getRequest(), Utilities.globalSettings.getString("dummy param name") + "=z"), req.getResponse(), req.getHttpService());
        }

        ArrayList<PartialParam> params = Utilities.getQueryParams(req.getRequest());

        for (IParameter param : params) {
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

        if (param != null && scan instanceof ParamScan && config.getBoolean("key input name")) {
            key.append(param.getName());
            key.append(param.getType());
        }

        if (config.getBoolean("key method")) {
            key.append(method);
        }

        if (config.getBoolean("key path")) {
            key.append(Utilities.getPathFromRequest(req.getRequest()).split("[?]", 1)[0]);
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
