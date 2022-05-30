package burp;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

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
