/*
 * Copyright (C) 2006-2008 Alfresco Software Limited.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

 * As a special exception to the terms and conditions of version 2.0 of 
 * the GPL, you may redistribute this Program in connection with Free/Libre 
 * and Open Source Software ("FLOSS") applications as described in Alfresco's 
 * FLOSS exception.  You should have recieved a copy of the text describing 
 * the FLOSS exception, and it is also available here: 
 * http://www.alfresco.com/legal/licensing"
 */
package org.alfresco.jlan.server.memory;

import java.util.LinkedList;

/**
 * Byte Buffer List Class
 *
 * <p>
 * Contains a list of byte buffers of the same size. The list has an initial and
 * maximum size.
 *
 * @author gkspencer
 */
public class ByteBufferList {

    // Buffer size, initial allocation and maximum allocation
    private final int m_bufSize;

    private final int m_initAlloc;
    private final int m_maxAlloc;

    // Byte buffers
    private final LinkedList<byte[]> m_bufList;

    // Count of buffers currently allocated out
    private int m_allocCount;

    // Statistics
    private long m_statAllocs;
    private long m_statWaits;
    private long m_statWaitExpired;

    /**
     * Class constructor
     *
     * @param bufSize int
     * @param initAlloc int
     * @param maxAlloc int
     */
    public ByteBufferList(int bufSize, int initAlloc, int maxAlloc) {
        m_bufSize = bufSize;
        m_initAlloc = initAlloc;
        m_maxAlloc = maxAlloc;
        // Validate the settings
        if (m_bufSize <= 0 || m_initAlloc < 0 || m_maxAlloc <= 0 || (m_initAlloc > m_maxAlloc)) {
            throw new RuntimeException("Invalid ByteBufferList parameters, size=" + m_bufSize + ", alloc=" + m_initAlloc + "/" + m_maxAlloc);
        }
        // Allocate the initial buffer
        m_bufList = new LinkedList<>();
        allocateInitialBuffers();
    }

    /**
     * Return the buffer size
     *
     * @return int
     */
    public final int getBufferSize() {
        return m_bufSize;
    }

    /**
     * Return the initial allocation size
     *
     * @return int
     */
    public final int getInitialAllocation() {
        return m_initAlloc;
    }

    /**
     * Return the maximum allocation size
     *
     * @return int
     */
    public final int getMaximumAllocation() {
        return m_maxAlloc;
    }

    /**
     * Return the count of available buffers
     *
     * @return int
     */
    public final int getAvailableCount() {
        return m_bufList.size();
    }

    /**
     * Return the count of buffers currently allocated out
     *
     * @return int
     */
    public final int getAllocatedCount() {
        return m_allocCount;
    }

    /**
     * Return the allocations statistic
     *
     * @return long
     */
    public final long getStatAllocationCounter() {
        return m_statAllocs;
    }

    /**
     * Return the allocation wait statistic
     *
     * @return long
     */
    public final long getStatAllocationWaits() {
        return m_statWaits;
    }

    /**
     * Return the allocation wait expired statistic
     *
     * @return long
     */
    public final long getStatAllocationWaitsExpired() {
        return m_statWaitExpired;
    }

    /**
     * Allocate a buffer
     *
     * @param waitTime long
     * @return byte[]
     */
    public final byte[] allocateBuffer(long waitTime) {
        // Use the buffer list as the lock
        byte[] buf = null;
        synchronized (m_bufList) {
            // Check if there is a buffer available
            if (!m_bufList.isEmpty()) {
                // Remove a buffer from the available list
                buf = m_bufList.remove();
                m_allocCount++;
                // Update the stats
                m_statAllocs++;
            } else if (m_allocCount < m_maxAlloc) {
                // Allocate a new buffer for this request
                buf = new byte[m_bufSize];
                m_allocCount++;
                // Update the stats
                m_statAllocs++;
            } else if (waitTime > 0) {
                try {
                    // Update the stats
                    m_statWaits++;
                    // Wait for a buffer to be released
                    m_bufList.wait(waitTime);
                    // Check if there is a buffer
                    if (m_bufList.size() > 0) {
                        buf = m_bufList.remove(0);
                        m_allocCount++;
                    } else {
                        // Update the stats
                        m_statWaitExpired++;
                    }
                } catch (InterruptedException ex) {
                }
            }
        }
        // Return the allocated buffer, or null if there are no buffers available
        return buf;
    }

    /**
     * Release a buffer back to the pool
     *
     * @param buf byte[]
     */
    public final void releaseBuffer(byte[] buf) {
        // Make sure it is one of our buffers
        if (buf == null || buf.length != m_bufSize) {
            return;
        }
        // Use the buffer list as the lock
        synchronized (m_bufList) {
            // If the list is empty then signal that a buffer is available
            if (m_bufList.isEmpty()) {
                m_bufList.notify();
            }
            // Release the buffer back to the available list
            m_bufList.add(buf);
            m_allocCount--;
        }
    }

    /**
     * Shrink the buffer list back to the initial allocation size
     *
     * @return Count of buffers released
     */
    public final int shrinkList() {
        // Check if the buffer list has more than the initial allocation of buffers
        int removedCnt = 0;
        if (m_bufList.size() > m_initAlloc) {
            // Use the buffer list as the lock
            synchronized (m_bufList) {
                // Remove buffers from the available buffer list
                while (m_bufList.size() > m_initAlloc) {
                    m_bufList.remove();
                    removedCnt++;
                }
            }
        }
        // Return the count of buffers removed from the list
        return removedCnt;
    }

    /**
     * Allocate the initial byte buffer list
     */
    private void allocateInitialBuffers() {
        // Allocte the byte buffers
        if (getInitialAllocation() > 0) {
            for (int i = 0; i < getInitialAllocation(); i++) {
                m_bufList.add(new byte[getBufferSize()]);
            }
        }
    }

    /**
     * Return the buffer list as a string
     *
     * @return String
     */
    @Override
    public String toString() {
        StringBuilder str = new StringBuilder();
        str.append("[Bufsize=");
        str.append(getBufferSize());
        str.append(",Init=");
        str.append(getInitialAllocation());
        str.append(",Max=");
        str.append(getMaximumAllocation());
        str.append(",Avail=");
        str.append(getAvailableCount());
        str.append(",Alloc=");
        str.append(getAllocatedCount());
        str.append(",Stats=");
        str.append(getStatAllocationCounter());
        str.append("/");
        str.append(getStatAllocationWaits());
        str.append("/");
        str.append(getStatAllocationWaitsExpired());
        str.append("]");
        return str.toString();
    }
}
