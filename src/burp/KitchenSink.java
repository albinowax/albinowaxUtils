package burp;
import java.util.List;

public class KitchenSink extends ParamScan {

    KitchenSink(String name) {
        super(name);
        for (Scan scan: BulkScan.scans) {
            scanSettings.importSettings(scan.scanSettings);
        }
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        for (Scan scan: BulkScan.scans) {
            if (scan == this) {
                continue;
            }
            scan.doScan(baseReq, service);
        }
        return null;
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        for (Scan scan: BulkScan.scans) {
            if (scan instanceof ParamScan && scan != this) {
                ((ParamScan)scan).doScan(baseRequestResponse, insertionPoint);
            }
        }
        return null;
    }
}