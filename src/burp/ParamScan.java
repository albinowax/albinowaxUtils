package burp;

import java.util.List;

abstract class ParamScan extends Scan {
    public ParamScan(String name) {
        super(name);
        // param-scan settings
        scanSettings.register("params: dummy", false, "When doing a parameter-based scan, add a dummy parameter to every request");
        //genericSettings.register("params: cookies", false);
        //genericSettings.register("special params", false);
        scanSettings.register("dummy param name", "utm_campaign");
        scanSettings.register("params: query", true, "When doing a parameter-based scan, scan query params");
        scanSettings.register("params: body", true, "When doing a parameter-based scan, scan body params");
        scanSettings.register("params: cookie", false, "When doing a parameter-based scan, scan cookies");
        scanSettings.register("params: scheme", false, "When doing a parameter-based scan over HTTP/2, scan the :scheme header");
        scanSettings.register("params: scheme-host", false, "When doing a parameter-based scan over HTTP/2, create a fake host in the :scheme header and scan it");
        scanSettings.register("params: scheme-path", false, "When doing a parameter-based scan over HTTP/2, create a fake path in the :scheme header and scan it");
    }

    abstract List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint);

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // todo convert insertion point into appropriate format
        return doScan(baseRequestResponse, insertionPoint);
    }

}
