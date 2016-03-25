package com.surfs.nas.mnt;

import com.surfs.nas.client.SurfsDiskSize;
import com.surfs.nas.client.SurFile;
import com.surfs.nas.error.VolumeNotFoundException;
import com.surfs.nas.transport.ThreadPool;
import java.io.IOException;
import org.alfresco.jlan.server.filesys.DiskDeviceContext;

public class SurDeviceContext extends DiskDeviceContext {

    private final SurMntDiskSize surfsDiskSize;
    private final SurDevicePermission surDevicePermission;
    private boolean useable = true;

    public SurDeviceContext(SurFile sf) throws IOException {
        super(sf.getPath());
        surfsDiskSize = new SurMntDiskSize(sf, this);
        surDevicePermission = new SurDevicePermission(sf.getPath());
    }

    /**
     * @return the surfsDiskSize
     */
    public SurfsDiskSize getSurfsDiskSize() {
        return surfsDiskSize;
    }

    /**
     * 运行
     */
    public void open() {
        surDevicePermission.start();
        surfsDiskSize.start();
    }

    @Override
    public void CloseContext() {
        super.CloseContext();
        ThreadPool.stopThread(surfsDiskSize);
        ThreadPool.stopThread(surDevicePermission);
    }

    /**
     * @return the surDevicePermission
     */
    public SurDevicePermission getSurDevicePermission() {
        return surDevicePermission;
    }

    /**
     * @return the useable
     */
    public boolean isUseable() {
        return useable;
    }

    private class SurMntDiskSize extends SurfsDiskSize {

        SurDeviceContext surDeviceContext = null;

        public SurMntDiskSize(SurFile root, SurDeviceContext surDeviceContext) {
            super(root);
            this.surDeviceContext = surDeviceContext;
        }

        @Override
        protected void getDirSpace() throws IOException {
            try {
                super.getDirSpace();
            } catch (VolumeNotFoundException e) {
                surDeviceContext.useable = false;
            }
        }
    }
}
