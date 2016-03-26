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

import com.surfs.nas.client.SurFile;
import java.io.IOException;
import org.alfresco.jlan.server.filesys.FileAttribute;
import org.alfresco.jlan.server.filesys.FileInfo;
import org.alfresco.jlan.server.filesys.SearchContext;
import org.alfresco.jlan.util.WildCard;

public class SurFileSearchContext extends SearchContext {

    private final int m_attr;
    private WildCard m_wildcard;
    private boolean m_single;
    private SurFile[] m_list;
    private int m_idx;
    private final SurFile m_root;

    SurFileSearchContext(SurFile searchPath, String searchString, int attrib) throws IOException {
        this.m_attr = attrib;
        this.setSearchString(searchString);
        if (searchString != null && WildCard.containsWildcards(searchString) == false) {
            setSingleFileSearch(true);
            m_root = new SurFile(searchPath, searchString);
        } else {
            m_root = searchPath;
            if (m_root.isDirectory()) {
                if (searchString == null) {
                    setSingleFileSearch(true);
                } else {
                    m_list = m_root.listFiles();
                    setSingleFileSearch(false);
                    m_wildcard = new WildCard(searchString, false);
                }
            }
        }
        m_idx = 0;
    }

    @Override
    public int getResumeId() {
        return m_idx;
    }

    @Override
    public boolean hasMoreFiles() {
        if (m_single == true && m_idx > 0) {
            return false;
        } else if (m_list != null && m_idx >= m_list.length) {
            return false;
        }
        return true;
    }

    @Override
    public boolean nextFileInfo(FileInfo info) {
        if (!m_root.exists()) {
            return false;
        }
        boolean infoValid = false;
        try {
            if (isSingleFileSearch()) {
                if (m_idx == 0) {
                    m_idx++;
                    if (!m_root.exists()) {
                        return false;
                    }
                    int fattr = 0;
                    long flen = 0L;
                    if (m_root.isDirectory()) {
                        fattr = FileAttribute.Directory;
                    } else {
                        flen = m_root.length();
                    }
                    info.setFileName(m_root.getName());
                    info.setSize(flen);
                    info.setFileAttributes(fattr);
                    info.setFileId(m_root.getFileId());
                    long modifyDate = m_root.lastModified();
                    info.setModifyDateTime(modifyDate);
                    info.setChangeDateTime(modifyDate);
                    info.setCreationDateTime(modifyDate);
                    infoValid = true;
                }
            } else if (m_list != null && m_idx < m_list.length) {
                boolean foundMatch = false;
                SurFile curFile = m_list[m_idx++];
                while (foundMatch == false && curFile != null) {
                    if (m_wildcard.matchesPattern(curFile.getName()) == true) {
                        if (FileAttribute.hasAttribute(m_attr, FileAttribute.Directory) && curFile.isDirectory()) {
                            foundMatch = true;
                        } else if (curFile.isFile()) {
                            foundMatch = true;
                        }
                    }
                    if (foundMatch == false) {
                        if (m_idx < m_list.length) {
                            curFile = m_list[m_idx++];
                        } else {
                            curFile = null;
                        }
                    }
                }
                if (curFile != null) {
                    if (!curFile.exists()) {
                        return false;
                    }
                    int fattr = 0;
                    long flen = 0L;
                    String fname = curFile.getName();
                    if (curFile.isDirectory()) {
                        fattr = FileAttribute.Directory;
                        if (fname.startsWith(".")) {
                            fattr += FileAttribute.Hidden;
                        }
                    } else {
                        flen = curFile.length();
                        if (fname.equalsIgnoreCase("Desktop.ini")
                                || fname.equalsIgnoreCase("Thumbs.db")
                                || fname.startsWith(".")) {
                            fattr += FileAttribute.Hidden;
                        }
                    }
                    info.setFileName(curFile.getName());
                    info.setSize(flen);
                    info.setFileAttributes(fattr);
                    info.setFileId(curFile.getFileId());
                    long modifyDate = curFile.lastModified();
                    info.setModifyDateTime(modifyDate);
                    info.setChangeDateTime(modifyDate);
                    info.setCreationDateTime(modifyDate);
                    infoValid = true;
                }
            }
        } catch (java.io.FileNotFoundException e) {
            return false;
        } catch (Exception r) {
            
        }
        return infoValid;
    }

    @Override
    public String nextFileName() {
        try {
            if (m_root.exists()) {
                if (!m_root.isDirectory()) {
                    if (m_idx == 0) {
                        m_idx++;
                        return m_root.getName();
                    } else {
                        return null;
                    }
                } else if (m_list != null && m_idx < m_list.length) {
                    while (m_idx < m_list.length) {
                        String fname = m_list[m_idx++].getName();
                        if (m_wildcard.matchesPattern(fname)) {
                            return fname;
                        }
                    }
                }
            }
        } catch (java.io.FileNotFoundException e) {
            return null;
        } catch (IOException ex) {
            
        }
        return null;
    }

    @Override
    public boolean restartAt(int resumeId) {
        if (m_list == null || resumeId >= m_list.length) {
            return false;
        }
        m_idx = resumeId;
        return true;
    }

    @Override
    public boolean restartAt(FileInfo info) {
        boolean restartOK = false;
        m_idx--;
        if (m_list != null) {
            while (m_idx > 0 && restartOK == false) {
                if (m_list[m_idx].getName().compareTo(info.getFileName()) == 0) {
                    restartOK = true;
                } else {
                    m_idx--;
                }
            }
        }
        return restartOK;
    }

    /**
     * Set the wildcard/single file search flag.
     *
     * @param single boolean
     */
    protected final void setSingleFileSearch(boolean single) {
        m_single = single;
    }

    /**
     * Determine if this is a wildcard or single file/directory type search.
     *
     * @return boolean
     */
    protected final boolean isSingleFileSearch() {
        return m_single;
    }
}
