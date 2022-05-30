package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

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
            for (int i = 0; i < issues.length; i++) {
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
