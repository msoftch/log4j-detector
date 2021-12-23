/*
 * Copyright 2021 M. Hautle
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package log4jdetector;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.security.ProtectionDomain;
import java.time.LocalDateTime;
import java.util.Properties;
import java.util.UUID;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;

/**
 * Java agent looking for log4j classes and writing the result to the standard
 * output and optionally to a file.<br>
 * Use this agent to asses wherever a running java application uses log4j and
 * thus may be vulnerable to CVE-2021-44228 (Log4Shell).<br>
 * To mitigate the vulnerability check out https://logging.apache.org/log4j/2.x/
 * or have a look at a "runtime" solution
 * https://github.com/corretto/hotpatch-for-apache-log4j2<br>
 * <br>
 * Dynamic agent registration copied from
 * https://github.com/corretto/hotpatch-for-apache-log4j2
 * 
 * @author M. Hautle
 * 
 */
public class Detector implements ClassFileTransformer {
    /** System property to get the language version of the JVM. */
    private static final String JVM_LANGUAGE_VERSION = "java.specification.version";

    /** Type string for Log4j v1 (legacy) candidate detections. */
    private static final String LEGACY_LOG4J_CANDIDATE = "LegacyLog4jCandidate";

    /** Type string for Log4j v1 (legacy) detections. */
    private static final String LEGACY_LOG4J = "LegacyLog4j";

    /** Type string for Log4j v2 candidate detections. */
    private static final String LOG4J_CANDIDATE = "Log4j2Candidate";

    /** Type string for Log4j v2 detections. */
    private static final String LOG4J = "Log4j2";

    /** Last part of the class name of a log4j V1 logger. */
    private static final String LOGGER_V1 = ".log4j.Logger";

    /** Exclusion for the {@link #LOGGER_V1} partial match - this FQN is a Log4j v2 interface. */
    private static final String NON_LOGGER_V1 = "org.apache.logging.log4j.Logger";

    /** FQN of a log4j V1 logger. */
    private static final String LOGGER_V1_FULL = "org.apache.log4j.Logger";

    /** JVM internal class name version of {@link #LOGGER_V1}. */
    private static final String LOGGER_V1_INT = LOGGER_V1.replace('.', '/');

    /** JVM internal class name version of {@link #NON_LOGGER_V1}. */
    private static final String NON_LOGGER_V1_INT = NON_LOGGER_V1.replace('.', '/');

    /** JVM internal class name version of {@link #LOGGER_V1_FULL}. */
    private static final String LOGGER_V1_FULL_INT = LOGGER_V1_FULL.replace('.', '/');

    /** Last part of the class name of a log4j V2 logger. */
    private static final String LOGGER_V2 = ".log4j.core.Logger";

    /** FQN of a log4j V2 logger. */
    private static final String LOGGER_V2_FULL = "org.apache.logging.log4j.core.Logger";

    /** JVM internal class name version of {@link #LOGGER_V2}. */
    private static final String LOGGER_V2_INT = LOGGER_V2.replace('.', '/');

    /** JVM internal class name version of {@link #LOGGER_V2_INT}. */
    private static final String LOGGER_V2_FULL_INT = LOGGER_V2_INT.replace('.', '/');

    /**
     * Last part of the log4j v2 JndiLookup class (the one containing the vulnerability).
     */
    private static final String JNDI_LOOKUP_CLASS = ".log4j.core.lookup.JndiLookup";

    /**
     * FQN of log4j v2 JndiLookup class (the one containing the vulnerability).
     */
    private static final String JNDI_LOOKUP_CLASS_FULL = "org.apache.logging.log4j.core.lookup.JndiLookup";

    /** JVM internal class name version of {@link #JNDI_LOOKUP_CLASS}. */
    private static final String JNDI_LOOKUP_CLASS_INT = JNDI_LOOKUP_CLASS.replace('.', '/');

    /** JVM internal class name version of {@link #JNDI_LOOKUP_CLASS_FULL}. */
    private static final String JNDI_LOOKUP_CLASS_FULL_INT = JNDI_LOOKUP_CLASS_FULL.replace('.', '/');

    /** Property specifying the agent version */
    private static final String DETECTOR_AGENT_VERSION = "log4jdetectorVer";

    /** Property specifying the system property used to detect this instance when run as "controller". */
    private static final String DETECTOR_CONTROLLER_ID = "log4jdetectorController";

    /** The agent version. */
    private static final String AGENT_VERSION = "0.2";

    /** The agent argument to specify an optional output file. */
    private static final String OUTPUT_PATH = "outputPath";

    /** The log streams to write to. */
    private PrintStream[] log;

    static {
        // set the version of this agent
        System.setProperty(DETECTOR_AGENT_VERSION, AGENT_VERSION);
    }

    /**
     * @param outputPath The file to write to or null
     */
    public Detector(File outputPath) throws Exception {
        if (outputPath != null) {
            log = new PrintStream[] { System.out, new PrintStream(new FileOutputStream(outputPath, true), true) };
        } else {
            log = new PrintStream[] { System.out };
        }
    }

    /**
     * Premain - used by static agent.
     * 
     * @param agentArgs
     *            Optionally {@link #OUTPUT_PATH}=&lt;some path&gt;
     * @param inst
     *            The instrumentation
     * @throws Exception
     *             If an error occurred
     */
    public static void premain(String agentArgs, Instrumentation inst) throws Exception {
        System.out.println("<Register log4jdetector agent>");
        inst.addTransformer(new Detector(getOutputPath(agentArgs)), true);
    }

    /**
     * Agent - used by runtime attached agent.
     * 
     * @param agentArgs
     *            Optionally {@link #OUTPUT_PATH}=&lt;some path&gt;
     * @param inst
     *            The instrumentation
     * @throws Exception
     *             If an error occurred
     */
    public static void agentmain(String agentArgs, Instrumentation inst) throws Exception {
        System.out.println("<Running log4jdetector agent>");
        new Detector(getOutputPath(agentArgs)).printLoadedClasses(inst);
        System.out.println("<log4jdetector done>");
    }

    /**
     * @param agentArgs
     *            The agent args
     * @return The output file or null
     */
    private static File getOutputPath(String agentArgs) {
        if (agentArgs != null && agentArgs.startsWith(OUTPUT_PATH + "=")) {
            final File f = new File(agentArgs.substring(OUTPUT_PATH.length() + 1));
            final File parent = f.getParentFile();
            if (parent != null) {
                parent.mkdirs();
            }
            return f;
        }
        return null;
    }

    /**
     * Print out all currently loaded classes.
     * 
     * @param inst
     *            The instrumentation
     */
    private void printLoadedClasses(Instrumentation inst) {
        for (Class c : inst.getAllLoadedClasses()) {
            final String className = c.getName();
            // use hard coded checks - should be somewhat faster than a for loop
            if (className.equals(JNDI_LOOKUP_CLASS_FULL) || className.equals(LOGGER_V2_FULL)) {
                log(LOG4J, className, c.getClassLoader());
            } else if (className.equals(LOGGER_V1_FULL)) {
                log(LEGACY_LOG4J, className, c.getClassLoader());
            } else if (className.endsWith(JNDI_LOOKUP_CLASS) || className.endsWith(LOGGER_V2)) {
                log(LOG4J_CANDIDATE, className, c.getClassLoader());
            } else if (className.endsWith(LOGGER_V1) && !className.equals(NON_LOGGER_V1)) {
                log(LEGACY_LOG4J_CANDIDATE, className, c.getClassLoader());
            }
        }
    }

    /**
     * Log the given class and its location.
     * 
     * @param type
     *            The entry type
     * @param clazz
     *            The class name
     * @param cl
     *            The used classloader or null
     */
    private void log(String type, String clazz, ClassLoader cl) {
        logOut("<" + LocalDateTime.now().toString() + "> " + type + ": " + clazz + " @" + resolvePath(clazz, cl));
    }

    /**
     * Log to all {@link #log} streams.
     * 
     * @param str The string to log
     */
    private void logOut(String str) {
        for (PrintStream out : log) {
            out.println(str);
        }
    }

    /**
     * @param className
     *            The class name
     * @param cl
     *            The owning classloader or null for the system loader
     * @return The location from where the class was loaded
     */
    private static String resolvePath(String className, ClassLoader cl) {
        if (cl == null) {
            cl = ClassLoader.getSystemClassLoader();
        }
        final URL rawURL = cl.getResource(className.replace('.', '/') + ".class");
        if (rawURL == null) {
            return "<unknown>";
        }
        final String protocol = rawURL.getProtocol();
        if ("jar".equals(protocol)) {
            // jar file - return only the location of the jar file
            final String spec = rawURL.getFile();
            final int separator = spec.indexOf("!/");
            if (separator > 0) {
                return spec.substring(0, separator);
            }
            return rawURL.toString();
        }

        if ("bundle".equals(protocol) || "bundleresource".equals(protocol)) {
            // osgi (probably felix or equinox)
            try {
                final Object bundle = cl.getClass().getMethod("getBundle").invoke(cl);
                final Class<?> bundleClass = Class.forName("org.osgi.framework.Bundle");
                final String symbolicName = String.valueOf(bundleClass.getMethod("getSymbolicName").invoke(bundle));
                final String location = String.valueOf(bundleClass.getMethod("getLocation").invoke(bundle));
                if (location != null) {
                    return symbolicName + " Location: " + location;
                }
                if (symbolicName != null) {
                    return symbolicName;
                }
            } catch (Exception e) {
                // simply ignore - this is a best effort implementation to get the bundle name from the classloader
            }
        }
        return rawURL.toString();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] transform(ClassLoader loader, final String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer)
            throws IllegalClassFormatException {
        try {
            if (className != null) {
                // use hard coded checks - should be somewhat faster than a for loop
                if (className.equals(JNDI_LOOKUP_CLASS_FULL_INT) || className.equals(LOGGER_V2_FULL_INT)) {
                    log(LOG4J, className, loader);
                } else if (className.equals(LOGGER_V1_FULL_INT)) {
                    log(LEGACY_LOG4J, className, loader);
                } else if (className.endsWith(JNDI_LOOKUP_CLASS_INT) || className.endsWith(LOGGER_V2_INT)) {
                    log(LOG4J_CANDIDATE, className, loader);
                } else if (className.endsWith(LOGGER_V1_INT) && !className.equals(NON_LOGGER_V1_INT)) {
                    log(LEGACY_LOG4J_CANDIDATE, className, loader);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static boolean loadInstrumentationAgent(String[] pids, File outputFolder) throws Exception {
        boolean succeeded = true;
        // Create agent jar file on the fly
        File jarFile = createAgentJar();
        String we = getUID("self");
        for (String pid : pids) {
            try {
                // Check if we're running under the same UID like the target
                // JVM. If not, log warning as it might fail to attach.
                if (we != null && !we.equals(getUID(pid))) {
                    log("\nWarning: patching for JVM process " + pid + " might fail because it runs under a different user");
                    log("  Our uid == " + we + ", their uid == " + getUID(pid));
                }
                final VirtualMachine vm = VirtualMachine.attach(pid);
                // If the target VM is patched with an other version then skip.
                // Notice that the agent class gets loaded by the system
                // class loader, so we can't unload or update it. Re-deploying the agent
                // just reruns 'agentmain()' from the already loaded agent version.
                final Properties props = vm.getSystemProperties();
                if (props == null) {
                    log("Error: could not verify '" + DETECTOR_AGENT_VERSION + "' in JVM process " + pid);
                    continue;
                }
                final String version = props.getProperty(DETECTOR_AGENT_VERSION);
                if (AGENT_VERSION.equals(version)) {
                    log("JVM process " + pid + " is already patched - rerun the listing anyway");
                } else if (version != null) {
                    log("Skipping patch for JVM process " + pid + ", patch version " + version + " already applied");
                    continue;
                }
                // apply patch to target vm
                final String outputPath = outputFolder != null ? OUTPUT_PATH + "=" + new File(outputFolder, "log4jdetector_" + pid + ".log").getAbsolutePath()
                        : null;
                vm.loadAgent(jarFile.getAbsolutePath(), outputPath);
            } catch (Exception e) {
                succeeded = false;
                e.printStackTrace(System.out);
                log("Error: couldn't loaded the agent into JVM process " + pid);
                log("  Are you running as a different user (including root) than process " + pid + "?");
                continue;
            }
            log("Successfully loaded the agent into JVM process " + pid);
            log("  Look at stdout of JVM process " + pid + " for more information");
            if (outputFolder != null) {
                log("  or check the log files in " + outputFolder.getAbsolutePath());
            }
        }
        return succeeded;
    }

    /**
     * Put this class in a agent jar - used for runtime instrumentation.<br>
     * We do this instead of assuming that we are loaded from a jar, to allow
     * executing the runtime instrumentation to be started from an IDE (i.e.
     * without building the jar first).
     * 
     * @return The jar file
     * @throws IOException
     * @throws FileNotFoundException
     * @throws Exception
     */
    private static File createAgentJar() throws IOException, FileNotFoundException, Exception {
        String clazz = Detector.class.getName();
        Manifest m = new Manifest();
        m.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        m.getMainAttributes().put(new Attributes.Name("Agent-Class"), clazz);
        m.getMainAttributes().put(new Attributes.Name("Can-Redefine-Classes"), "true");
        m.getMainAttributes().put(new Attributes.Name("Can-Retransform-Classes"), "true");
        File jarFile = File.createTempFile("agent", ".jar");
        jarFile.deleteOnExit();
        try (JarOutputStream jar = new JarOutputStream(new FileOutputStream(jarFile), m)) {
            String className = clazz.replace('.', '/');
            jar.putNextEntry(new JarEntry(className + ".class"));
            copyBytecode(className, jar);
        }
        return jarFile;
    }

    /**
     * Log the given information.
     * 
     * @param string
     *            A string
     */
    private static void log(String string) {
        System.out.println(string);
    }

    /**
     * Copy the specified class to the given output stream
     * 
     * @param clazz
     *            The class name as internal name (i.e. with / instead of . in
     *            the name)
     * @param out
     *            The output stream to write to
     * @throws Exception
     */
    private static void copyBytecode(String clazz, OutputStream out) throws Exception {
        try (InputStream is = Detector.class.getResourceAsStream("/" + clazz + ".class")) {
            copyBytes(is, out);
        }
    }

    /**
     * Copy the content of the input stream to the output stream
     * 
     * @param in
     *            The source
     * @param out
     *            The destination
     * @throws IOException
     */
    private static void copyBytes(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[4096];
        for (int len = in.read(buf); len != -1; len = in.read(buf)) {
            out.write(buf, 0, len);
        }
    }

    /**
     * @param in
     *            A input stream
     * @return The data as byte[]
     * @throws IOException
     */
    private static byte[] toBytes(InputStream in) throws IOException {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            copyBytes(in, out);
            return out.toByteArray();
        }
    }

    // This only works on Linux but it is harmless as it returns 'null'
    // on error and null values for the UID will be ignored later on.
    private static String getUID(String pid) {
        try {
            return Files.lines(FileSystems.getDefault().getPath("/proc/" + pid + "/status"))
                    .filter(l -> l.startsWith("Uid:")).findFirst().get().split("\\s")[1];
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Creates the specified folder.
     * 
     * @param value
     *            A path or null
     * @return The folder or null
     */
    private static File mkdirs(String value) {
        if (value == null) {
            return null;
        }
        File f = new File(value);
        f.mkdirs();
        return f;
    }

    /**
     * Load the given tools jar "dynamically" and run main on this class again.
     * 
     * @param args
     *            The main args
     * @param tools
     *            The tools jar location
     * @throws Exception
     */
    private static void rerunWithToolsJar(String[] args, File tools) throws Exception {
        log("Adding tools.jar from " + tools.getAbsolutePath() + " to classpath");
        final String ourClass = Detector.class.getName();
        new URLClassLoader(new URL[] { tools.toURI().toURL() }, Detector.class.getClassLoader()) {
            @Override
            protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                if (ourClass.equals(name)) {
                    // special handling for our class - load it in this
                    // new class loader so that it has access to the
                    // automatically added tools.jar
                    Class<?> c = findLoadedClass(name);
                    if (c != null) {
                        return c;
                    }
                    // get "raw" data from the parent classloader as our
                    // class loader contains only the tools jar
                    try (InputStream in = getParent().getResourceAsStream(name.replace('.', '/').concat(".class"))) {
                        byte[] buf = toBytes(in);
                        c = defineClass(name, buf, 0, buf.length);
                    } catch (IOException e) {
                        throw new ClassNotFoundException("Error reloading class " + name + ": " + e.getMessage(), e);
                    }
                    if (resolve) {
                        resolveClass(c);
                    }
                    return c;
                }
                return super.loadClass(name, resolve);
            }
        }.loadClass(ourClass).getDeclaredMethod("main", String[].class).invoke(null, (Object) args);
    }

    public static void main(String args[]) throws Exception {
        if (Detector.class.getResource("/sun.jvmstat.monitor.MonitoredVm".replace('.', '/') + ".class") == null) {
            final File tools = new File(System.getProperty("java.home"), "../lib/tools.jar");
            if (tools.exists()) {
                rerunWithToolsJar(args, tools);
                return;
            }
            log("tools.jar is missing and could not be found - add it manually to the classpath: java -cp log4j-detector.jar:<java-home>/lib/tools.jar "
                    + Detector.class.getName());
            System.exit(1);
        }
        if (args.length == 0) {
            // mark our JVM so that we can exclude id from the pid list
            final String selfId = UUID.randomUUID().toString();
            System.setProperty(DETECTOR_CONTROLLER_ID, selfId);
            final String ourJavaVersion = System.getProperty(JVM_LANGUAGE_VERSION);
            final String ourUser = System.getProperty("user.name");
            log("usage: java [-Doutput=<base/output/path/for/log>] -jar log4j-detector.jar <pid> [<pid> ...]");
            log("currently visible java processes for " + ourUser + "@ Java Version " + ourJavaVersion + ":");
            for (VirtualMachineDescriptor desc : VirtualMachine.list()) {
                final VirtualMachine jvm = VirtualMachine.attach(desc);
                try {
                    final Properties sysProps = jvm.getSystemProperties();
                    if (selfId.equals(sysProps.get(DETECTOR_CONTROLLER_ID))) {
                        // our process
                        continue;
                    }
                    final String user = sysProps.getProperty("user.name");
                    final String agent = sysProps.getProperty(DETECTOR_AGENT_VERSION);
                    if (agent != null) {
                        // already instrumented process
                        log("Instrumented: " + desc.id() + ": " + desc.displayName() + " - Java Version: " + sysProps.getProperty("java.version") + " User: "
                                + user + " Agent Version: " + agent);
                    } else if (ourJavaVersion.equals(sysProps.getProperty(JVM_LANGUAGE_VERSION)) && ourUser.equals(user)) {
                        log(desc.id() + ": " + desc.displayName() + " - Java Version: " + sysProps.getProperty("java.version") + " User: " + user);
                    } else {
                        // jvm with different user or different java version - we may not be able to patch it properly!
                        log("( " + desc.id() + ": " + desc.displayName() + " - Java Version: " + sysProps.get("java.version") + " User: " + user + " )");
                    }
                } catch (Exception e) {
                    log(desc.id() + ": " + desc.displayName() + " - Error while getting further infos: " + e.getMessage());
                } finally {
                    jvm.detach();
                }
            }
            System.exit(1);
        }
        final boolean succeeded = loadInstrumentationAgent(args, mkdirs(System.getProperty("output")));
        if (succeeded) {
            System.exit(0);
        } else {
            log("Errors occurred deploying hot patch. The target JVM may still be patched. Please look for a message\n"
                    + "like '<Running log4jdetector agent>' in stdout of the target JVM.");
            System.exit(1);
        }
    }
}
