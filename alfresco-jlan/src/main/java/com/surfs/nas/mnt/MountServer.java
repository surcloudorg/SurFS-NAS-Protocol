package com.surfs.nas.mnt;

import org.alfresco.jlan.app.JLANServer;

public class MountServer {

    public static void main(String[] args) {
        if (args == null || args.length == 0) {
            args = new String[]{"bin/surmount.xml"};
        }
        JLANServer.main(args);
    }
}
