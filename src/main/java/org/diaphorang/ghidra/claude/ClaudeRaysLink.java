/*
 * Diaphora, a binary diffing tool
 * Copyright (c) 2015-2026 Joxean Koret
 * Copyright (c) 2026 ClaudeMonkey (Java port, Claude-Rays/diaphora-ng-ghidra)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package org.diaphorang.ghidra.claude;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Diaphora-ng - link to the API of Claude-Rays Decompiler for Ghidra.
 *
 * <p>Its service is found at run time by name, so there is no build time
 * dependency. Every extension is loaded by the same class loader in Ghidra,
 * so the class is visible when the extension is installed; the service exists when its
 * plugin (ClaudeRaysPlugin) is enabled in the tool.
 */
public final class ClaudeRaysLink {

    static final String SERVICE_CLASS = "org.clauderays.ghidra.api.ClaudeRaysService";
    static final String PLUGIN_CLASS = "org.clauderays.ghidra.ui.ClaudeRaysPlugin";

    private ClaudeRaysLink() {
    }

    private static Class<?> serviceClass() {
        try {
            return Class.forName(SERVICE_CLASS);
        }
        catch (ClassNotFoundException | LinkageError e) {
            return null;
        }
    }

    /** The service of the tool, null if the extension is not installed or its plugin not enabled. */
    static Object service(PluginTool tool, boolean addPlugin) {
        Class<?> c = serviceClass();
        if (c == null || tool == null) {
            return null;
        }
        Object svc = tool.getService(c);
        if (svc == null && addPlugin) {
            // the equivalent of load_plugin("clauderays-decompiler")
            try {
                tool.addPlugin(PLUGIN_CLASS);
            }
            catch (Exception e) {
                return null;
            }
            svc = tool.getService(c);
        }
        return svc;
    }

    /** Is the extension installed (its classes are loaded)? */
    public static boolean installed() {
        return serviceClass() != null;
    }

    /**
     * The API version of the Claude-Rays Decompiler plugin of the tool: -1 if it is
     * not installed or not enabled, 0 if it has no API (an older version).
     */
    public static int version(PluginTool tool, boolean addPlugin) {
        Object svc = service(tool, addPlugin);
        if (svc == null) {
            return -1;
        }
        try {
            Method m = svc.getClass().getMethod("apiVersion");
            return ((Number) m.invoke(svc)).intValue();
        }
        catch (ReflectiveOperationException | ClassCastException e) {
            return 0;
        }
    }

    /**
     * diffFunctions(requestJson): from the Swing thread it shows the modal task
     * dialog of Claude-Rays Decompiler (with Cancel) and blocks until the answer.
     * null if the API is missing.
     */
    public static String diff(PluginTool tool, String requestJson) {
        Object svc = service(tool, false);
        if (svc == null) {
            return null;
        }
        try {
            Method m = serviceClass().getMethod("diffFunctions", String.class);
            return (String) m.invoke(svc, requestJson);
        }
        catch (InvocationTargetException e) {
            throw new IllegalStateException("Claude-Rays Decompiler failed: " + e.getCause(), e.getCause());
        }
        catch (ReflectiveOperationException e) {
            return null;
        }
    }

    /** The same with an explicit program and monitor (any thread, no dialog); null if the API is missing. */
    public static String diff(PluginTool tool, Program program, String requestJson, TaskMonitor monitor) {
        Object svc = service(tool, false);
        if (svc == null) {
            return null;
        }
        try {
            Method m = serviceClass().getMethod("diffFunctions", Program.class, String.class, TaskMonitor.class);
            return (String) m.invoke(svc, program, requestJson, monitor);
        }
        catch (InvocationTargetException e) {
            throw new IllegalStateException("Claude-Rays Decompiler failed: " + e.getCause(), e.getCause());
        }
        catch (ReflectiveOperationException e) {
            return null;
        }
    }
}
