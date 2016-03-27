/*
 * Copyright (C) 2016 Alfresco Software Limited.
 *
 * This file is part of Alfresco
 *
 * Alfresco is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Alfresco is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Alfresco. If not, see <http://www.gnu.org/licenses/>.
 */
/***************************************************************************
 *
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
package org.alfresco.jlan.oncrpc;

import java.util.concurrent.LinkedBlockingQueue;
import org.alfresco.jlan.oncrpc.nfs.NFS;

/**
 * RPC Request Queue Class
 *
 * <p>
 * Provides a request queue for a thread pool of worker threads.
 *
 * @author gkspencer
 */
public class RpcRequestQueue {

    private final LinkedBlockingQueue<RpcPacket> m_queue = new LinkedBlockingQueue<>();
    private final LinkedBlockingQueue<RpcPacket> m_queue_head = new LinkedBlockingQueue<>();

    /**
     * Add a request to the queue
     *
     * @param req RpcPacket
     */
    public final void addRequest(RpcPacket req) {
        int pid = req.getProcedureId();
        if (pid == NFS.ProcWrite || pid == NFS.ProcRead || pid == NFS.ProcCommit) {
            m_queue.add(req);
        } else {
            m_queue_head.add(req);
        }
    }

    /**
     * Remove a request from the head of the queue
     *
     * @return RpcPacket
     * @exception InterruptedException
     */
    public final RpcPacket removeRequestHead() throws InterruptedException {
        return m_queue_head.take();
    }

    /**
     * Remove a request from the head of the queue
     *
     * @return RpcPacket
     * @exception InterruptedException
     */
    public final RpcPacket removeRequest() throws InterruptedException {
        return m_queue.take();
    }
}
