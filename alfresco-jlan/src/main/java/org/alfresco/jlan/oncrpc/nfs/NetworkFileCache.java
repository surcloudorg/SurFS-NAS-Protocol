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
/***************************************************************************
 *
 * Copyright (C) 2016 SurCloud.
 *
 * This file was modified by SurCloud and is part of JLAN for SurFS, you
 * can redistribute and/or modify it under the same license terms as above.
 *
 * JLAN for SurFS is likewise distributed WITHOUT ANY WARRANTY.
 */
package org.alfresco.jlan.oncrpc.nfs;

 
import com.surfs.nas.log.LogFactory;
import com.surfs.nas.log.Logger;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

import org.alfresco.jlan.server.SrvSession;
import org.alfresco.jlan.server.filesys.DiskInterface;
import org.alfresco.jlan.server.filesys.NetworkFile;
import org.alfresco.jlan.server.filesys.TreeConnection;

/**
 * Network File Cache Class
 *
 * <p>
 * Caches the network files that are currently being accessed by the NFS server.
 *
 * @author gkspencer
 */
public class NetworkFileCache {

    private final static Logger log = LogFactory.getLogger();

    //	Default file timeout
    public static final long DefaultFileTimeout = 20000L;  //  20 seconds
    public static final long ClosedFileTimeout = 60000L;   //  60 seconds

    //	Network file cache, key is the file id
    private final Map<Integer, FileEntry> m_fileCache;

    //	File expiry thread
    private final FileExpiry m_expiryThread;

    //	File timeouts
    private long m_fileIOTmo = DefaultFileTimeout;
    private long m_fileCloseTmo = ClosedFileTimeout;

    //	Debug enable flag
    private boolean m_debug = false;

    /**
     * File Entry Class
     */
    protected class FileEntry {

        //Network file and closed flag

        private final NetworkFile m_file;
        //Disk share connection
        private final TreeConnection m_conn;
        // Session that last accessed the file
        private SrvSession m_sess;
        private boolean m_closed;
        //File timeout
        private long m_timeout;

        /**
         * Class constructor
         *
         * @param file NetworkFile
         * @param conn TreeConnection
         * @param sess SrvSession
         */
        public FileEntry(NetworkFile file, TreeConnection conn, SrvSession sess) {
            m_file = file;
            m_conn = conn;
            m_sess = sess;
            updateTimeout();
        }

        /**
         * Return the file timeout
         *
         * @return long
         */
        public final long getTimeout() {
            return m_timeout;
        }

        /**
         * Return the network file
         *
         * @return NetworkFile
         */
        public final NetworkFile getFile() {
            return m_file;
        }

        /**
         * Return the disk share connection
         *
         * @return TreeConnection
         */
        public final TreeConnection getConnection() {
            return m_conn;
        }

        /**
         * Get the session that last accessed the file
         *
         * @return SrvSession
         */
        public final SrvSession getSession() {
            return m_sess;
        }

        /**
         * Update the file timeout
         */
        public final void updateTimeout() {
            m_timeout = System.currentTimeMillis() + m_fileIOTmo;
        }

        /**
         * Update the file timeout
         *
         * @param tmo long
         */
        public final void updateTimeout(long tmo) {
            m_timeout = tmo;
        }

        /**
         * Set the session that last accessed the file
         *
         * @param sess SrvSession
         */
        public final void setSession(SrvSession sess) {
            m_sess = sess;
        }

        /**
         * Check if the network file has been closed due to no I/O activity
         *
         * @return boolean
         */
        public final boolean isClosed() {
            return m_closed;
        }

        /**
         * Close the file
         */
        public final void closeFile() {
            if (m_file != null) {
                try {
                    m_file.closeFile();
                    m_closed = true;
                } catch (IOException ex) {
                }
            }
        }

        /**
         * Open the network file
         */
        public final void openFile() {
            if (m_file != null) {
                try {
                    m_file.openFile(false);
                    m_closed = false;
                } catch (IOException ex) {
                }
            }
        }
    };

    /**
     * File Expiry Thread Class
     */
    protected class FileExpiry implements Runnable {

        //Expiry thread
        private final Thread m_thread;

        //Shutdown flag
        private boolean m_shutdown;

        /**
         * Class Constructor
         *
         * @param name String
         */
        public FileExpiry(String name) {
            m_thread = new Thread(this);
            m_thread.setDaemon(true);
            m_thread.setName("NFSFileExpiry_" + name);
            m_thread.start();
        }

        /**
         * Main thread method
         */
        @Override
        public void run() {
            long times = 0;
            while (m_shutdown == false) {//	Loop until shutdown
                try {
                    Thread.sleep(m_fileIOTmo / 2);
                } catch (InterruptedException ex) {
                }
                long timeNow = System.currentTimeMillis();
                List<Entry<Integer, FileEntry>> list = new ArrayList<>(m_fileCache.entrySet());
                times = times + (m_fileIOTmo / 2);
                if (times > 1000 * 60 * 10) {
                    log.debug("NetworkFileCache: size={0}", new Object[]{list.size()});
                    times = 0;
                }
                for (Entry<Integer, FileEntry> ent : list) {
                    FileEntry fentry = ent.getValue();
                    if (fentry != null && fentry.getTimeout() < timeNow) {
                        NetworkFile netFile = fentry.getFile();//Get the network file
                        //Check if the file has an I/O request pending, if so then reset the file expiry time for the file
                        if (netFile.hasIOPending()) {
                            //Update the expiry time for the file entry
                            fentry.updateTimeout();
                            log.debug("NFSFileExpiry: I/O pending file={0}, fid={1}",
                                    new Object[]{fentry.getFile().getFullName(), ent.getKey()});
                        } else {
                            //Check if the network file is closed, if not then close the file to release the file handle
                            //but keep the file entry in the file cache for a while as the file may be re-opened
                            if (fentry.isClosed() == false) {
                                // Close the network file
                                fentry.closeFile();
                                // Update the file entry timeout to keep the file in the cache for a while
                                fentry.updateTimeout(System.currentTimeMillis() + m_fileCloseTmo);
                                log.debug("NFSFileExpiry: Closed file={0}, fid={1} (cached)",
                                        new Object[]{fentry.getFile().getFullName(), ent.getKey()});
                            } else {
                                //File entry has expired, remove it from the cache
                                m_fileCache.remove(ent.getKey());
                                //Close the file via the disk interface
                                try {
                                    //	Get the disk interface
                                    DiskInterface disk = (DiskInterface) fentry.getConnection().getInterface();
                                    //	Close the file
                                    disk.closeFile(fentry.getSession(), fentry.getConnection(), netFile);
                                } catch (IOException ex) {
                                }
                                log.debug("NFSFileExpiry: Closed file={0}, fid={1}",
                                        new Object[]{fentry.getFile().getFullName(), ent.getKey()});
                            }
                        }
                    }
                }

            }
        }

        /**
         * Request the file expiry thread to shutdown
         */
        public final void requestShutdown() {
            //	Set the shutdown flag
            m_shutdown = true;
            //	Wakeup the thread
            try {
                m_thread.interrupt();
            } catch (Exception ex) {
            }
            //	Wait for the expiry thread to complete
            try {
                m_thread.join(m_fileIOTmo);
            } catch (Exception ex) {
            }
        }
    };

    /**
     * Class constructor
     *
     * @param name String
     */
    public NetworkFileCache(String name) {
        //Create the file cache
        m_fileCache = new ConcurrentHashMap<>();
        //Start the file expiry thread
        m_expiryThread = new FileExpiry(name);
    }

    /**
     * Determine if debug output is enabled
     *
     * @return boolean
     */
    public final boolean hasDebug() {
        return m_debug;
    }

    /**
     * Add a file to the cache
     *
     * @param file NetworkFile
     * @param conn TreeConnection
     * @param sess SrvSession
     */
    public final void addFile(NetworkFile file, TreeConnection conn, SrvSession sess) {
        m_fileCache.put(file.getFileId(), new FileEntry(file, conn, sess));
    }

    /**
     * Remove a file from the cache
     *
     * @param id
     */
    public final void removeFile(int id) {
        m_fileCache.remove(id);
    }

    /**
     * Find a file via the file id
     *
     * @param id int
     * @param sess SrvSession
     * @return NetworkFile
     */
    public final NetworkFile findFile(int id, SrvSession sess) {
        FileEntry fentry = m_fileCache.get(id);
        //Return the file, or null if not found
        if (fentry != null) {
            //	Update the file timeout
            fentry.updateTimeout();
            // Check if the file is open
            if (fentry.isClosed()) {
                fentry.openFile();
            }
            // Return the file
            return fentry.getFile();
        }
        return null;
    }

    /**
     * Return the count of entries in the cache
     *
     * @return int
     */
    public final int numberOfEntries() {
        return m_fileCache.size();
    }

    /**
     * Close the expiry cache, close and remove all files from the cache and
     * stop the expiry thread.
     */
    public final void closeAllFiles() {
        List<FileEntry> list = new ArrayList<>(m_fileCache.values());

        for (FileEntry entry : list) {
            entry.updateTimeout(0L);//	Expire the file entry
        }
        //Shutdown the expiry thread, this should close the files
        m_expiryThread.requestShutdown();
    }

    /**
     * Enable/disable debug output
     *
     * @param ena boolean
     */
    public final void setDebug(boolean ena) {
        m_debug = ena;
    }

    /**
     * Set the I/O cache timer value
     *
     * @param ioTimer long
     */
    public final void setIOTimer(long ioTimer) {
        m_fileIOTmo = ioTimer;
    }

    /**
     * Set the close file cache timer value
     *
     * @param closeTimer long
     */
    public final void setCloseTimer(long closeTimer) {
        m_fileCloseTmo = closeTimer;
    }
}
