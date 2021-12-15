# log4j-detector
Log4j Detector - use to check if a application could be affected by Log4Shell (CVE-2021-44228)

This is a simple java agent which prints out if Log4j classes are present in a running application.
Use it to check if you need to take further steps to secure the application or if it does not use log4j at all.

The check is based on class names of loaded classes, thus of the classes actively used by the application.

# Usage

## Output description

The output of the agent will look like the following example:

    <Running log4jdetector agent>                                     
    Log4jCandidate: org.apache.logging.log4j.core.Logger @<class location>
    Log4jCandidate: org.apache.logging.log4j.core.lookup.JndiLookup @<class location>
    LegacyLog4jCandidate: org.apache.log4j.Logger @<class location>
    <log4jdetector done>

The entries `<Running log4jdetector agent>` and `<log4jdetector done>` will only be printed to the system out of the process - they simply indicate that the agent was run.

Entries starting with `Log4jCandidate` specify classes which may be Log4j 2 classes, check the specific class name and the location to determine if it is a Log4j class or only a class named similarly (the tool lists classes ending like the Log4j classes to allow you to detect also renamed Log4j classes - some applications/libraries may have choosen to rename the base package of the Log4j).

Entries starting with `LegacyLog4jCandidate` specify classes which may be Log4j 1 classes, thus classes belonging to the legacy version of Log4j - they are printed out so that you know that a Log4j library is present but not the vulnerable one (this way if you are told that a application uses Log4j that you can confirm that but that you also know that it is not the affected one).

The part after the '@' specifies the location of the class as the owning ClassLoader sees it - in normal applications this will likely be a jar/file URL, in some cases it may be a framework specific URL (at least with some OSGi frameworks).

## Runtime attachment
This is the "easy" way, if runtime attachment is allowed by the JVM and you have access to the host running the application then this is the way to go.

**Attention**: When run like this the agent only analyzes the currently loaded classes! This is kind of a snapshot view. When using this attaching method, make sure that the application already processed some requests so that all normally used classes are loaded and thus can be seen by the agent.


The agent supports runtime attachment, the simples way to use it is to start it on the machine running the application to inspect:

    java -jar log4j-detector.jar

without arguments it prints out the visible java processes - thus the input for the real attachment call:

    java [-Doutput=<base/output/path/for/log/>] -jar log4j-detector.jar <pid> [<pid> ...]

after the agent is attached it iterates over all loaded classes and prints out the matching ones to the system output and optionally to a file in the directory specified by `-Doutput`

## Static attachment
If the *Runtime attachment* does not work for your case, then use the static attachment. Here the agent will be passed as start parameter to the application and it will run as long as the applications JVM. This way the agent prints out every (potential) Log4j class which gets loaded.

**Be aware** that this way of running the agent involves a performance penalty as every class loaded by the JVM will run throught the agent!


Simply specify the java agent in your java command line:

    -javaagent:log4j-detector.jar[=outputPath=<path/to/log/file.log>]
  
thus the final line would look something like
  
    java -classpath <class-path> -javaagent:log4j-detector.jar[=outputPath=<base/output/path/for/log>] <main-class> <arguments>
