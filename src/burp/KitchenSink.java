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
        Utilities.out("Kicking off request scans");
        for (Scan scan: BulkScan.scans) {
            if (scan == this) {
                continue;
            }
            Utilities.out("Queueing reuest scan: "+scan.name);
            scan.doScan(baseReq, service);
        }
        return null;
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        Utilities.out("Kicking off param scans");
        for (Scan scan: BulkScan.scans) {
            if (scan instanceof ParamScan && scan != this) {
                Utilities.out("Queueing param scan: "+scan.name);
                ((ParamScan)scan).doScan(baseRequestResponse, insertionPoint);
            }
        }
        return null;
    }
}