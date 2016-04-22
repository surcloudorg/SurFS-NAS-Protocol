/*
 * Copyright (C) 2016 SurCloud.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * http://www.gnu.org/licenses/licenses.html
 */ 

package org.alfresco.jlan.oncrpc.nfs;

import static org.alfresco.jlan.oncrpc.nfs.NFSServer.MaxRequestSize;

public abstract class NFSInfo {

    private static NFSInfo nfsinfo = null;

    public static synchronized void setNFSInfo(NFSInfo info) {
        nfsinfo = info;
    }

    public static int getMaxSize() {
        if (nfsinfo == null) {
            return 65535;
        } else {
            int size = nfsinfo.getBlockSize();
            
            size = 1024 * (size / 1024) - 1;
            if (size < 65535) {
                size = 65535;
            }
            if (size > MaxRequestSize) {
                size = MaxRequestSize;
            }
            return size;
        }
    }

    public abstract int getBlockSize();
}
