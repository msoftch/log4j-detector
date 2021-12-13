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
import java.util.Properties;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import com.sun.tools.attach.VirtualMachine;

import sun.jvmstat.monitor.MonitoredHost;
import sun.jvmstat.monitor.MonitoredVm;
import sun.jvmstat.monitor.MonitoredVmUtil;
import sun.jvmstat.monitor.VmIdentifier;

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
    /** Last part of the class name of a log4j V1 logger. */
    private static final String LOGGER_V1 = ".log4j.Logger";

    /** JVM internal class name version of {@link #LOGGER_V1}. */
    private static final String LOGGER_V1_INT = LOGGER_V1.replace('.', '/');

    /** Last part of the class name of a log4j V2 logger. */
    private static final String LOGGER_V2 = ".log4j.core.Logger";

    /** JVM internal class name version of {@link #LOGGER_V2}. */
    private static final String LOGGER_V2_INT = LOGGER_V2.replace('.', '/');

    /**
     * Last part of the log4j v2 JndiLookup class (the one containing the
     * vulnerability).
     */
    private static final String JNDI_LOOKUP_CLASS = ".log4j.core.lookup.JndiLookup";

    /** JVM internal class name version of {@link #JNDI_LOOKUP_CLASS}. */
    private static final String JNDI_LOOKUP_CLASS_INT = JNDI_LOOKUP_CLASS.replace('.', '/');

    /** Property specifying the agent version */
    private static final String DETECTOR_AGENT_VERSION = "log4jdetectorVer";

    /** The agent version. */
    private static final String AGENT_VERSION = "0.1";

    /** The agent argument to specify an optional output file. */
    private static final String OUTPUT_PATH = "outputPath";

    /** The log streams to write to. */
    private PrintStream[] log;

    static {
        // set the version of this agent
        System.setProperty(DETECTOR_AGENT_VERSION, AGENT_VERSION);
    }

    /**
     * @param outputPath
     *            The file to write to or null
     */
    public Detector(File outputPath) throws Exception {
        if (outputPath != null) {
            log = new PrintStream[] { System.out, new PrintStream(new FileOutputStream(outputPath), true) };
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
    }

    /**
     * @param agentArgs
     *            The agent args
     * @return The output file or null
     */
    private static File getOutputPath(String agentArgs) {
        if (agentArgs != null && agentArgs.startsWith(OUTPUT_PATH + "=")) {
            return new File(agentArgs.substring(OUTPUT_PATH.length() + 1));
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
            if (className.endsWith(JNDI_LOOKUP_CLASS) || className.endsWith(LOGGER_V2)) {
                log("Log4jcandidate", className, c.getClassLoader());
            } else if (className.endsWith(LOGGER_V1)) {
                log("LegacyLog4jCandidate", className, c.getClassLoader());
            }
        }
    }

    private void log(String type, String clazz, ClassLoader cl) {
        for (PrintStream out : log) {
            out.println(type + ": " + clazz + " @" + resolvePath(clazz, cl));
        }
    }

    /**
     * @param className
     *            The class name
     * @param cl
     *            The owning classloader or null for the system loader
     * @return The URL to load the given class from the passed classloader
     */
    private static URL resolvePath(String className, ClassLoader cl) {
        // FIXME add special handling for osgi classloaders?
        if (cl == null) {
            cl = ClassLoader.getSystemClassLoader();
        }
        return cl.getResource(className.replace('.', '/') + ".class");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] transform(ClassLoader loader, final String className, Class<?> classBeingRedefined,
            ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        try {
            if (className != null) {
                // use hard coded checks - should be somewhat faster than a for
                // loop
                if (className.endsWith(JNDI_LOOKUP_CLASS_INT) || className.endsWith(LOGGER_V2_INT)) {
                    log("Log4jcandidate", className, loader);
                } else if (className.endsWith(LOGGER_V1_INT)) {
                    log("LegacyLog4jCandidate", className, loader);
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
                    log("\nWarning: patching for JVM process " + pid
                            + " might fail because it runs under a different user");
                    log("  Our uid == " + we + ", their uid == " + getUID(pid));
                }
                VirtualMachine vm = VirtualMachine.attach(pid);
                // If the target VM is already patched then skip.
                // Notice that the agent class gets loaded by the system
                // class loader, so we
                // can't unload or update it. If we'd re-deploy the agent
                // one more time, we'd
                // just rerun 'agentmain()' from the already loaded agent
                // version.
                Properties props = vm.getSystemProperties();
                if (props == null) {
                    log("Error: could not verify '" + DETECTOR_AGENT_VERSION + "' in JVM process " + pid);
                    continue;
                }
                String version = props.getProperty(DETECTOR_AGENT_VERSION);
                if (version != null) {
                    log("Skipping patch for JVM process " + pid + ", patch version " + version + " already applied");
                    continue;
                }
                // unpatched target VM, apply patch
                final String outputPath = outputFolder != null
                        ? OUTPUT_PATH + "=" + new File(outputFolder, "log4jdetector_" + pid + ".log").getAbsolutePath()
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
     * @return
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

    private static void log(String string) {
        System.out.println(string);
    }

    private static void copyBytecode(String myName, OutputStream out) throws Exception {
        try (InputStream is = Detector.class.getResourceAsStream("/" + myName + ".class")) {
            copyBytes(is, out);
        }
    }

    /**
     * @param in
     * @param out
     * @throws IOException
     */
    private static void copyBytes(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[4096];
        for (int len = in.read(buf); len != -1; len = in.read(buf)) {
            out.write(buf, 0, len);
        }
    }

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
            log("no tools jar on the classpath - trying to locate it");
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
            final String ourClazz = Detector.class.getName();
            log("usage: java -jar log4j-detector.jar <pid> [<pid> ...]");
            log("Specify output path for logs: -Doutput=<base/output/path/for/log>");
            log("currently visible java processes:");
            MonitoredHost host = MonitoredHost.getMonitoredHost((String) null);
            for (Integer p : host.activeVms()) {
                MonitoredVm jvm = host.getMonitoredVm(new VmIdentifier(p.toString()));
                String mainClass = MonitoredVmUtil.mainClass(jvm, true);
                if (ourClazz.equals(mainClass)) {
                    // skip our selfs
                    continue;
                }
                log(p + ": " + mainClass);
            }
            System.exit(1);
        }
        boolean succeeded = loadInstrumentationAgent(args, mkdirs(System.getProperty("output")));
        if (succeeded) {
            System.exit(0);
        } else {
            log("Errors occurred deploying hot patch. The target JVM may still be patched. Please look for a message\n"
                    + "like '<Running log4jdetector agent>' in stdout of the target JVM.");
            System.exit(1);
        }

    }
}
