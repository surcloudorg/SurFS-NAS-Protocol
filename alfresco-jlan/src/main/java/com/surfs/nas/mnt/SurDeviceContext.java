/*
 * Copyright (C) 2016 SurCloud.
 *
 * This file is part of JLAN for SurFS
 *
 * JLAN for SurFS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * JLAN for SurFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with JLAN for SurFS. If not, see <http://www.gnu.org/licenses/>.
 */

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
