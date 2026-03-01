package gdbplugin;

public class GDBPluginOutputParser {

    public String parseOutput(String output) {
        if (output == null || output.isEmpty()) {
            return output;
        }

        String trimmedOutput = output.trim();

        if (trimmedOutput.startsWith("^")) {
            return parseResultRecord(trimmedOutput);
        }

        if (trimmedOutput.startsWith("*")) {
            return parseExecAsyncOutput(trimmedOutput);
        }

        if (trimmedOutput.startsWith("=")) {
            return parseNotifyAsyncOutput(trimmedOutput);
        }

        if (trimmedOutput.startsWith("~")) {
            return parseConsoleStreamOutput(trimmedOutput);
        }

        if (trimmedOutput.startsWith("@")) {
            return parseTargetStreamOutput(trimmedOutput);
        }

        if (trimmedOutput.startsWith("&")) {
            return parseLogStreamOutput(trimmedOutput);
        }

        if (trimmedOutput.startsWith("(gdb)")) {
            return ">> " + output;
        }

        return output;
    }

    private String parseResultRecord(String output) {
        if (output.startsWith("^done")) {
            return ">> GDB command completed: " + output;
        }
        if (output.startsWith("^running")) {
            return ">> Program running";
        }
        if (output.startsWith("^connected")) {
            return ">> Connected to target";
        }
        if (output.startsWith("^error")) {
            return ">> GDB error: " + output;
        }
        if (output.startsWith("^exit")) {
            return ">> GDB exited";
        }
        return output;
    }

    private String parseExecAsyncOutput(String output) {
        if (output.startsWith("*stopped")) {
            return ">> Program stopped: " + output;
        }
        if (output.startsWith("*running")) {
            return ">> Program running: " + output;
        }
        return output;
    }

    private String parseNotifyAsyncOutput(String output) {
        if (output.startsWith("=thread-created")) {
            return ">> Thread created: " + output;
        }
        if (output.startsWith("=thread-exited")) {
            return ">> Thread exited: " + output;
        }
        if (output.startsWith("=thread-selected")) {
            return ">> Thread selected: " + output;
        }
        if (output.startsWith("=thread-group-added")) {
            return ">> Thread group added: " + output;
        }
        if (output.startsWith("=thread-group-started")) {
            return ">> Thread group started: " + output;
        }
        if (output.startsWith("=thread-group-exited")) {
            return ">> Thread group exited: " + output;
        }
        if (output.startsWith("=library-loaded")) {
            return ">> Library loaded: " + output;
        }
        if (output.startsWith("=breakpoint-modified")) {
            return ">> Breakpoint modified: " + output;
        }
        if (output.startsWith("=cmd-param-changed")) {
            return ">> Command parameter changed: " + output;
        }
        return output;
    }

    private String parseConsoleStreamOutput(String output) {
        if (output.startsWith("~")) {
            String content = output.substring(1);
            if (content.startsWith("\"") && content.endsWith("\"")) {
                content = content.substring(1, content.length() - 1);
            }
            return "[console] " + content;
        }
        return output;
    }

    private String parseTargetStreamOutput(String output) {
        if (output.startsWith("@")) {
            String content = output.substring(1);
            if (content.startsWith("\"") && content.endsWith("\"")) {
                content = content.substring(1, content.length() - 1);
            }
            return "[target] " + content;
        }
        return output;
    }

    private String parseLogStreamOutput(String output) {
        if (output.startsWith("&")) {
            String content = output.substring(1);
            if (content.startsWith("\"") && content.endsWith("\"")) {
                content = content.substring(1, content.length() - 1);
            }
            return "[log] " + content;
        }
        return output;
    }
}
