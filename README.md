# log4j-detector
Log4j Detector - use to check if a application could be affected by Log4Shell (CVE-2021-44228)

This is a simple java agent which prints out if Log4j classes are present in a running application.
Use it to check if you need to take further steps to secure the application or if it does not use log4j at all.

The check is based on class names of loaded classes, thus of the classes actively used by the application.

# Usage

## Runtime attachment
This is the "easy" way, if runtime attachment is allowed by the JVM and you have access to the host running the application then this is the way to go.

**Attention**: When run like this the agent only analyzes the currently loaded classes! This is kind of a snapshot view.


The agent supports runtime attachment, the simples way to use it is to start it on the machine running the application to inspect:

    java -jar log4j-detector.jar

without arguments it prints out the visible java processes - thus the input for the real attachment call:

    java [-Doutput=<base/output/path/for/log>] -jar log4j-detector.jar <pid> [<pid> ...]

after the agent is attached it iterates over all loaded classes and prints out the matching ones to the system output and optionally to a file in the directory specified by `-Doutput`

## Static attachment
If the *Runtime attachment* does not work for your case, then use the static attachment. Here the agent will be passed as start parameter to the application and it will run as long as the applications JVM. This way the agent prints out every (potential) Log4j class which gets loaded.

**Be aware** that this way of running the agent involves a performance penalty as every class loaded by the JVM will run throught the agent!


Simply specify the java agent in your java command line:

    -javaagent:log4j-detector.jar[=outputPath=<base/output/path/for/log>]
  
thus the final line would look something like
  
    java -classpath <class-path> -javaagent:log4j-detector.jar[=outputPath=<base/output/path/for/log>] <main-class> <arguments>