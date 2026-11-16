package com.xanadu.browser;

import android.app.job.JobParameters;
import android.app.job.JobService;

public class MeshSyncJobService extends JobService {
    @Override
    public boolean onStartJob(final JobParameters params) {
        new Thread(() -> {
            try {
                LocalNodeServer headless = new LocalNodeServer(getApplicationContext(), 0);
                headless.runHeadlessMeshSync();
            } catch (Exception ignored) {
            } finally {
                jobFinished(params, false);
            }
        }, "xnd-mesh-job").start();
        return true;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        return true;
    }
}
