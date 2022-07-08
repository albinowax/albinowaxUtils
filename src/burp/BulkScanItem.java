package burp;

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
                Utilities.out("Skipping already-confirmed-vulnerable host: " + baseItem.host);
            }
            ScanPool engine = BulkScanLauncher.getTaskEngine();
            long done = engine.getCompletedTaskCount() + 1;

            Utilities.out("Completed request with key " + baseItem.getKey() + ": " + done + " of " + (engine.getQueue().size() + done) + " in " + (System.currentTimeMillis() - start) / 1000 + " seconds with " + Utilities.requestCount.get() + " requests");//, " + engine.candidates + " candidates and " + engine.findings + " findings ");
        } catch (Exception e) {
            Utilities.showError(e);
        }
    }
}
