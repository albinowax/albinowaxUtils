package burp;

import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

class BulkScanLauncher {

    private static ScanPool taskEngine;

    BulkScanLauncher(List<Scan> scans) {
        taskEngine = buildTaskEngine();
        Utilities.callbacks.registerContextMenuFactory(new OfferBulkScan(scans));
    }

    private static ScanPool buildTaskEngine() {
        BlockingQueue<Runnable> tasks;
        tasks = new LinkedBlockingQueue<>();

        Utilities.globalSettings.registerSetting("thread pool size", 8, "The maximum number of threads this tool will spin up. This roughly correlates with the number of concurrent requests. Increasing this value will make attacks run faster, and use more computer resources.");
        Utilities.globalSettings.registerSetting("canary", Utilities.randomString(8), "Static canary string used for input reflection detection sometimes");
        ScanPool taskEngine = new ScanPool(Utilities.globalSettings.getInt("thread pool size"), Utilities.globalSettings.getInt("thread pool size"), 10, TimeUnit.MINUTES, tasks);
        Utilities.globalSettings.registerListener("thread pool size", value -> {
            Utilities.out("Updating active thread pool size to " + value);
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
