package gdbplugin;

import java.io.*;
import java.math.BigInteger;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.listing.Program;

public class GDBPluginController {

    private Process gdb;

    private BufferedWriter gdbIn;
    private BufferedReader gdbOut;

    private final ExecutorService ioThreads = Executors.newFixedThreadPool(2);

    private final GDBPluginOutputParser outputParser = new GDBPluginOutputParser();

    public interface GdbStopListener {
        void onStopped(long pc);
    }

    private GdbStopListener stopListener;

    public interface GDBOutputListener {
        void onOutput(String line);
    }

    private GDBOutputListener outputListener;

    // function to write output on screen

    public void writeOutput(String output) {
        if (outputListener != null) {
            String parsedOutput = outputParser.parseOutput(output);
            outputListener.onOutput(parsedOutput);
        }
    }

    //Start commands

    public void startEverything(Program program, Integer port) {
        try {

            String programPath = program.getExecutablePath();

            if (programPath == null || programPath.isEmpty()) {
                throw new IllegalStateException("No executable path for the program!");
            }

            if (programPath.matches("^/[A-Z]:/.*")) {
                programPath = programPath.substring(1);
            }

            programPath = programPath.replace("\\", "/");

            startGdb();

            connectToProgram(programPath);

            writeOutput("GDB started");
        }
        catch (IOException e) {
            writeOutput("Failed to start GDB: " + e.getMessage());
        }
    }

    private void startGdb() throws IOException {
        ProcessBuilder pb = new ProcessBuilder(
            "gdb",
            "--interpreter=mi2");

        pb.redirectErrorStream(true);
        gdb = pb.start();

        gdbIn = new BufferedWriter(
            new OutputStreamWriter(gdb.getOutputStream()));
        gdbOut = new BufferedReader(
            new InputStreamReader(gdb.getInputStream()));

        ioThreads.submit(this::readGdbOutput);
    }

    private void connectToProgram(String programPath) throws IOException {
        String normalizedPath = programPath.replace("\\", "/");

        send("-gdb-set mi-async on");
        send("-file-exec-and-symbols \"" + normalizedPath + "\"");
        configureInferiorConsole();
        send("starti");
    }

    //Function to create a console that simulates real output of running the program

    private void configureInferiorConsole() throws IOException {
        String osName = System.getProperty("os.name", "").toLowerCase();
        if (osName.contains("win")) {
            send("-interpreter-exec console \"set new-console on\"");
            send("-interpreter-exec console \"set exec-wrapper cmd /k\"");
            send("-break-insert -f exit");
            send("-break-insert -f _exit");
        }
    }

    private Program currentProgram;

    public void resetEverything() {
        if (gdb != null)
            gdb.destroyForcibly();

        gdb = null;
        gdbIn = null;
        gdbOut = null;

        try {
            Thread.sleep(200);
        }
        catch (InterruptedException e) {
        }
    }

    public void restartProgram() {
        try {
            if (currentProgram == null) {
                writeOutput("No program loaded");
                return;
            }

            if (gdb != null) {
                send("-exec-abort");
            }

            send("-file-exec-and-symbols \"" + currentProgram.getExecutablePath() + "\"");
            send("-exec-run");

        }
        catch (IOException e) {
            writeOutput("Error restarting program: " + e.getMessage());
        }
    }

    public void setCurrentProgram(Program program, Integer port) {
        this.currentProgram = program;
    }

    //Breakpoint commands

    public void setBreakpoint(String location, Boolean temporary, Boolean hardware,
            Boolean disabled, String condition, Integer ignoreCount) throws IOException {
        if (location == null || location.isEmpty()) {
            throw new IllegalArgumentException("location must be specified");
        }

        StringBuilder sb = new StringBuilder("-break-insert");

        if (temporary != null && temporary)
            sb.append(" -t");
        if (hardware != null && hardware)
            sb.append(" -h");
        if (disabled != null && disabled)
            sb.append(" -d");
        if (condition != null && !condition.isEmpty())
            sb.append(" -c ").append(condition);
        if (ignoreCount != null)
            sb.append(" -i ").append(ignoreCount);

        sb.append(" ").append(location);

        send(sb.toString());
    }

    public void listBreakpoints() throws IOException {
        send("-break-list");
    }

    public void deleteBreakpoints(int... numbers) throws IOException {
        StringBuilder sb = new StringBuilder("-break-delete");
        if (numbers != null && numbers.length > 0) {
            for (int n : numbers)
                sb.append(" ").append(n);
        }
        send(sb.toString());
    }

    public void disableBreakpoints(int... numbers) throws IOException {
        StringBuilder sb = new StringBuilder("-break-disable");
        if (numbers != null && numbers.length > 0) {
            for (int n : numbers)
                sb.append(" ").append(n);
        }
        send(sb.toString());
    }

    public void enableBreakpoints(int... numbers) throws IOException {
        StringBuilder sb = new StringBuilder("-break-enable");
        if (numbers != null && numbers.length > 0) {
            for (int n : numbers)
                sb.append(" ").append(n);
        }
        send(sb.toString());
    }

    public void breakpointInfo(Integer number) throws IOException {
        if (number == null) {
            send("-break-info");
        }
        else {
            send("-break-info " + number);
        }
    }

    public void breakAfter(int breakpointNumber, Integer count) throws IOException {
        if (count == null) {
            send("-break-after " + breakpointNumber);
        }
        else {
            send("-break-after " + breakpointNumber + " " + count);
        }
    }

    public void setBreakpointCondition(int breakpointNumber, String condition) throws IOException {
        if (condition == null || condition.isEmpty()) {
            send("-break-condition " + breakpointNumber);
        }
        else {
            send("-break-condition " + breakpointNumber + " " + condition);
        }
    }

    public void setBreakpointConditionForced(int breakpointNumber, String condition)
            throws IOException {
        if (condition == null || condition.isEmpty()) {
            send("-break-condition --force " + breakpointNumber);
        }
        else {
            send("-break-condition --force " + breakpointNumber + " " + condition);
        }
    }

    public void setBreakpointCommands(int breakpointNumber, String... commands) throws IOException {
        StringBuilder sb = new StringBuilder("-break-commands " + breakpointNumber);
        if (commands != null && commands.length > 0) {
            for (String cmd : commands) {
                sb.append(" \"").append(cmd).append("\"");
            }
        }
        send(sb.toString());
    }

    //Watching commands

    public void dprintf(String location, String format, String... args) throws IOException {
        if (location == null || location.isEmpty()) {
            throw new IllegalArgumentException("location must be specified");
        }
        if (format == null || format.isEmpty()) {
            throw new IllegalArgumentException("format must be specified");
        }

        StringBuilder sb = new StringBuilder("-dprintf-insert ");
        sb.append(location).append(" \"").append(format).append("\"");

        if (args != null && args.length > 0) {
            for (String arg : args) {
                if (arg != null && !arg.isEmpty()) {
                    sb.append(" ").append(arg);
                }
            }
        }

        send(sb.toString());
    }

    public void watch(String expression, String type) throws IOException {
        if (expression == null || expression.isEmpty()) {
            throw new IllegalArgumentException("expression must be specified");
        }

        StringBuilder sb = new StringBuilder("-break-watch");

        if (type != null) {
            switch (type.toLowerCase()) {
                case "access":
                    sb.append(" -a");
                    break;
                case "read":
                    sb.append(" -r");
                    break;
                case "write":
                    sb.append(" -w");
                    break;
                default:
                    throw new IllegalArgumentException("Invalid watch type: " + type);
            }
        }

        sb.append(" ").append(expression);

        send(sb.toString());
    }

    public void watch(String expression) throws IOException {
        watch(expression, null);
    }

    public void setTracepointPasscount(int tracepointNumber, Integer passcount) throws IOException {
        if (passcount == null) {
            send("-break-passcount " + tracepointNumber);
        }
        else {
            send("-break-passcount " + tracepointNumber + " " + passcount);
        }
    }

    //Program setting commands

    public void setProgramArguments(String... args) throws IOException {
        StringBuilder sb = new StringBuilder("-exec-arguments");
        if (args != null && args.length > 0) {
            for (String arg : args) {
                if (arg != null && !arg.isEmpty()) {
                    sb.append(" ").append(arg);
                }
            }
        }
        send(sb.toString());
    }

    public void changeDirectory(String path) throws IOException {
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("path must be specified");
        }
        send("-environment-cd " + path);
    }

    public void environmentDirectory(String action, String... paths) throws IOException {
        StringBuilder sb = new StringBuilder("-environment-directory");
        if (action != null && !action.isEmpty()) {
            sb.append(" ").append(action);
        }
        if (paths != null && paths.length > 0) {
            for (String path : paths) {
                if (path != null && !path.isEmpty()) {
                    sb.append(" ").append(path);
                }
            }
        }
        send(sb.toString());
    }

    public void resetSourceDirectories() throws IOException {
        environmentDirectory("-r");
    }

    public void resetAndAddSourceDirectories(String... paths) throws IOException {
        environmentDirectory("-r", paths);
    }

    public void showSourceDirectories() throws IOException {
        environmentDirectory(null);
    }

    private void environmentPath(String action, String... paths) throws IOException {
        StringBuilder sb = new StringBuilder("-environment-path");
        if (action != null && !action.isEmpty()) {
            sb.append(" ").append(action);
        }
        if (paths != null && paths.length > 0) {
            for (String path : paths) {
                if (path != null && !path.isEmpty()) {
                    sb.append(" ").append(path);
                }
            }
        }
        send(sb.toString());
    }

    public void showEnvironmentPath() throws IOException {
        environmentPath(null);
    }

    public void addEnvironmentPath(String... paths) throws IOException {
        environmentPath(null, paths);
    }

    public void resetEnvironmentPath() throws IOException {
        environmentPath("-r");
    }

    public void resetAndAddEnvironmentPath(String... paths) throws IOException {
        environmentPath("-r", paths);
    }

    public void printWorkingDirectory() throws IOException {
        send("-environment-pwd");
    }

    //Thread commands

    public void threadInfo() throws IOException {
        threadInfo(null);
    }

    public void threadInfo(Integer threadId) throws IOException {
        if (threadId == null) {
            send("-thread-info");
        }
        else {
            send("-thread-info " + threadId);
        }
    }

    public void listThreadIds() throws IOException {
        send("-thread-list-ids");
    }

    public void selectThread(Integer threadId) throws IOException {
        if (threadId == null) {
            throw new IllegalArgumentException("threadId must be specified");
        }
        send("-thread-select " + threadId);
    }

    // Ada commands

    public void adaTaskInfo() throws IOException {
        adaTaskInfo(null);
    }

    private void adaTaskInfo(Integer taskId) throws IOException {
        if (taskId == null) {
            send("-ada-task-info");
        }
        else {
            send("-ada-task-info " + taskId);
        }
    }

    //Running commands

    //Run

    public void run() throws IOException {
        run(null, false, false);
    }

    public void runAndStopAtMain() throws IOException {
        run(null, true, false);
    }

    public void runAll() throws IOException {
        run(null, false, true);
    }

    public void runThreadGroup(String groupId) throws IOException {
        run(groupId, false, false);
    }

    private void run(String groupId, boolean startAtMain, boolean all) throws IOException {
        StringBuilder sb = new StringBuilder("-exec-run");
        if (startAtMain)
            sb.append(" --start");
        if (all)
            sb.append(" --all");
        if (groupId != null && !groupId.isEmpty())
            sb.append(" --thread-group ").append(groupId);
        send(sb.toString());
    }

    //Continue

    public void continueExec() throws IOException {
        continueExec(null, false, false);
    }

    public void continueReverse() throws IOException {
        continueExec(null, true, false);
    }

    public void continueAll() throws IOException {
        continueExec(null, false, true);
    }

    public void continueThreadGroup(String groupId) throws IOException {
        continueExec(groupId, false, false);
    }

    private void continueExec(String groupId, boolean reverse, boolean all) throws IOException {
        StringBuilder sb = new StringBuilder("-exec-continue");
        if (reverse)
            sb.append(" --reverse");
        if (all)
            sb.append(" --all");
        if (groupId != null && !groupId.isEmpty())
            sb.append(" --thread-group ").append(groupId);
        send(sb.toString());
    }

    //Interrupt
    public void interrupt() throws IOException {
        interrupt(null, false);
    }

    public void interruptAll() throws IOException {
        interrupt(null, true);
    }

    public void interruptThreadGroup(String groupId) throws IOException {
        interrupt(groupId, false);
    }

    private void interrupt(String groupId, boolean all) throws IOException {
        StringBuilder sb = new StringBuilder("-exec-interrupt");
        if (all)
            sb.append(" --all");
        if (groupId != null && !groupId.isEmpty())
            sb.append(" --thread-group ").append(groupId);
        send(sb.toString());
    }

    //Next/Step/Until

    public void next() throws IOException {
        next(false);
    }

    public void nextReverse() throws IOException {
        next(true);
    }

    private void next(boolean reverse) throws IOException {
        String cmd = "-exec-next" + (reverse ? " --reverse" : "");
        send(cmd);
    }

    public void step() throws IOException {
        step(false);
    }

    public void stepReverse() throws IOException {
        step(true);
    }

    private void step(boolean reverse) throws IOException {
        String cmd = "-exec-step" + (reverse ? " --reverse" : "");
        send(cmd);
    }

    public void until() throws IOException {
        until(null);
    }

    public void until(String location) throws IOException {
        String cmd =
            "-exec-until" + (location != null && !location.isEmpty() ? " " + location : "");
        send(cmd);
    }

    //Instruction

    public void nextInstruction() throws IOException {
        nextInstruction(false);
    }

    public void nextInstructionReverse() throws IOException {
        nextInstruction(true);
    }

    private void nextInstruction(boolean reverse) throws IOException {
        String cmd = "-exec-next-instruction" + (reverse ? " --reverse" : "");
        send(cmd);
    }

    public void stepInstruction() throws IOException {
        stepInstruction(false);
    }

    public void stepInstructionReverse() throws IOException {
        stepInstruction(true);
    }

    private void stepInstruction(boolean reverse) throws IOException {
        String cmd = "-exec-step-instruction" + (reverse ? " --reverse" : "");
        send(cmd);
    }

    //Finish/Return

    public void finish() throws IOException {
        finish(false);
    }

    public void finishReverse() throws IOException {
        finish(true);
    }

    private void finish(boolean reverse) throws IOException {
        String cmd = "-exec-finish" + (reverse ? " --reverse" : "");
        send(cmd);
    }

    public void returnFromFunction() throws IOException {
        send("-exec-return");
    }

    public void jump(String location) throws IOException {
        if (location == null || location.isEmpty()) {
            throw new IllegalArgumentException("Location must be specified for jump");
        }
        send("-exec-jump " + location);
    }

    //Stack commands

    public void enableFrameFilters() throws IOException {
        send("-enable-frame-filters");
    }

    public void stackInfoFrame() throws IOException {
        send("-stack-info-frame");
    }

    public void stackInfoDepth() throws IOException {
        stackInfoDepth(null);
    }

    public void stackInfoDepth(Integer maxDepth) throws IOException {
        String cmd = "-stack-info-depth" + (maxDepth != null ? " " + maxDepth : "");
        send(cmd);
    }

    public void stackListFrames() throws IOException {
        stackListFrames(null, null, false);
    }

    public void stackListFrames(int low, int high) throws IOException {
        stackListFrames(low, high, false);
    }

    public void stackListFramesNoFilters(int low, int high) throws IOException {
        stackListFrames(low, high, true);
    }

    private void stackListFrames(Integer low, Integer high, boolean noFrameFilters)
            throws IOException {
        StringBuilder sb = new StringBuilder("-stack-list-frames");
        if (noFrameFilters)
            sb.append(" --no-frame-filters");
        if (low != null && high != null)
            sb.append(" ").append(low).append(" ").append(high);
        send(sb.toString());
    }

    public void stackListArguments(int printValues) throws IOException {
        stackListArguments(printValues, null, null);
    }

    private void stackListArguments(int printValues, Integer low, Integer high) throws IOException {
        StringBuilder sb = new StringBuilder("-stack-list-arguments ").append(printValues);
        if (low != null && high != null)
            sb.append(" ").append(low).append(" ").append(high);
        send(sb.toString());
    }

    public void stackListLocals(int printValues) throws IOException {
        stackListLocals(false, false, printValues);
    }

    private void stackListLocals(boolean noFrameFilters, boolean skipUnavailable, int printValues)
            throws IOException {
        StringBuilder sb = new StringBuilder("-stack-list-locals ");
        if (noFrameFilters)
            sb.append("--no-frame-filters ");
        if (skipUnavailable)
            sb.append("--skip-unavailable ");
        sb.append(printValues);
        send(sb.toString());
    }

    public void stackListVariables(int printValues) throws IOException {
        stackListVariables(false, false, null, null, printValues);
    }

    public void stackListVariables(boolean noFrameFilters, boolean skipUnavailable, int printValues)
            throws IOException {
        stackListVariables(noFrameFilters, skipUnavailable, null, null, printValues);
    }

    public void stackListVariables(int threadId, int frame, int printValues) throws IOException {
        stackListVariables(false, false, threadId, frame, printValues);
    }

    private void stackListVariables(boolean noFrameFilters, boolean skipUnavailable,
            Integer threadId, Integer frame, int printValues) throws IOException {
        StringBuilder sb = new StringBuilder("-stack-list-variables ");
        if (noFrameFilters)
            sb.append("--no-frame-filters ");
        if (skipUnavailable)
            sb.append("--skip-unavailable ");
        if (threadId != null && frame != null)
            sb.append("--thread ").append(threadId).append(" --frame ").append(frame).append(" ");
        sb.append(printValues);
        send(sb.toString());
    }

    public void selectFrame(int frameNumber) throws IOException {
        send("-stack-select-frame " + frameNumber);
    }

    //Variable object commands

    public void enablePrettyPrinting() throws IOException {
        send("-enable-pretty-printing");
    }

    public void varCreate(String expression, boolean floating) throws IOException {
        if (expression == null || expression.isEmpty()) {
            throw new IllegalArgumentException("Expression must be specified");
        }
        String mode = floating ? "@" : "*";
        send("-var-create - " + mode + " " + expression);
    }

    public void varDelete(String name, boolean childrenOnly) throws IOException {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Variable name must be specified");
        }
        send("-var-delete " + (childrenOnly ? "-c " : "") + name);
    }

    public void varSetFormat(String name, String format) throws IOException {
        if (name == null || name.isEmpty() || format == null || format.isEmpty()) {
            throw new IllegalArgumentException("Both name and format must be specified");
        }
        send("-var-set-format " + name + " " + format);
    }

    public void varShowFormat(String name) throws IOException {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Variable name must be specified");
        }
        send("-var-show-format " + name);
    }

    public void varInfoNumChildren(String name) throws IOException {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Variable name must be specified");
        }
        send("-var-info-num-children " + name);
    }

    public void varListChildren(String name) throws IOException {
        varListChildren(name, null, null);
    }

    private void varListChildren(String name, Integer from, Integer to) throws IOException {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Variable name must be specified");
        }
        StringBuilder sb = new StringBuilder("-var-list-children --all-values " + name);
        if (from != null && to != null) {
            sb.append(" ").append(from).append(" ").append(to);
        }
        send(sb.toString());
    }

    public void varInfoType(String name) throws IOException {
        sendVarInfoCommand("-var-info-type", name);
    }

    public void varInfoExpression(String name) throws IOException {
        sendVarInfoCommand("-var-info-expression", name);
    }

    public void varInfoPathExpression(String name) throws IOException {
        sendVarInfoCommand("-var-info-path-expression", name);
    }

    public void varShowAttributes(String name) throws IOException {
        sendVarInfoCommand("-var-show-attributes", name);
    }

    private void sendVarInfoCommand(String cmd, String name) throws IOException {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Variable name must be specified");
        }
        send(cmd + " " + name);
    }

    public void varEvaluate(String name) throws IOException {
        varEvaluate(name, null);
    }

    private void varEvaluate(String name, String format) throws IOException {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Variable name must be specified");
        }
        String cmd = "-var-evaluate-expression";
        if (format != null && !format.isEmpty()) {
            cmd += " -f " + format;
        }
        cmd += " " + name;
        send(cmd);
    }

    public void varAssign(String name, String value) throws IOException {
        if (name == null || name.isEmpty() || value == null) {
            throw new IllegalArgumentException("Both name and value must be specified");
        }
        send("-var-assign " + name + " " + value);
    }

    public void varUpdateAll() throws IOException {
        send("-var-update --all-values *");
    }

    public void varUpdate(String name) throws IOException {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Variable name must be specified");
        }
        send("-var-update --all-values " + name);
    }

    public void varSetFrozen(String name, boolean frozen) throws IOException {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Variable name must be specified");
        }
        send("-var-set-frozen " + name + " " + (frozen ? "1" : "0"));
    }

    public void varSetUpdateRange(String name, Integer from, Integer to) throws IOException {
        if (name == null || name.isEmpty() || from == null || to == null) {
            throw new IllegalArgumentException("Name and range must be specified");
        }
        send("-var-set-update-range " + name + " " + from + " " + to);
    }

    public void varSetVisualizer(String name, String visualizer) throws IOException {
        if (name == null || name.isEmpty() || visualizer == null || visualizer.isEmpty()) {
            throw new IllegalArgumentException("Both name and visualizer must be specified");
        }
        send("-var-set-visualizer " + name + " " + visualizer);
    }

    //Dissasemble commands

    public void dataDisassembleRange(String start, String end) throws IOException {
        if (start == null || start.isEmpty() || end == null || end.isEmpty()) {
            throw new IllegalArgumentException("Both start and end addresses must be specified");
        }
        send("-data-disassemble -s " + start + " -e " + end + " -- 0");
    }

    public void dataDisassembleFunction(String function) throws IOException {
        if (function == null || function.isEmpty()) {
            throw new IllegalArgumentException("Function name must be specified");
        }
        send("-data-disassemble -a " + function + " -- 0");
    }

    public void dataDisassembleFileLine(String file, int line) throws IOException {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("File name must be specified");
        }
        send("-data-disassemble -f " + file + " -l " + line + " -- 0");
    }

    public void dataDisassembleFileLineCount(String file, int line, int count) throws IOException {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("File name must be specified");
        }
        send("-data-disassemble -f " + file + " -l " + line + " -n " + count + " -- 0");
    }

    public void dataDisassembleWithOpcodes(String start, String end) throws IOException {
        if (start == null || start.isEmpty() || end == null || end.isEmpty()) {
            throw new IllegalArgumentException("Both start and end addresses must be specified");
        }
        send("-data-disassemble -s " + start + " -e " + end + " --opcodes bytes -- 0");
    }

    public void dataDisassembleWithSource(String start, String end) throws IOException {
        if (start == null || start.isEmpty() || end == null || end.isEmpty()) {
            throw new IllegalArgumentException("Both start and end addresses must be specified");
        }
        send("-data-disassemble -s " + start + " -e " + end + " --source -- 0");
    }

    //Expression evaluation commands

    public void dataEvaluateExpression(String expr) throws IOException {
        if (expr == null || expr.isEmpty()) {
            throw new IllegalArgumentException("Expression must be specified");
        }
        send("-data-evaluate-expression \"" + expr + "\"");
    }

    //Register commands

    public void dataListChangedRegisters() throws IOException {
        send("-data-list-changed-registers");
    }

    public void dataListRegisterNames(int... regs) throws IOException {
        StringBuilder sb = new StringBuilder("-data-list-register-names");
        if (regs != null) {
            for (int r : regs)
                sb.append(" ").append(r);
        }
        send(sb.toString());
    }

    public void dataListRegisterValues(char format, int... regs) throws IOException {
        StringBuilder sb = new StringBuilder("-data-list-register-values " + format);
        if (regs != null) {
            for (int r : regs)
                sb.append(" ").append(r);
        }
        send(sb.toString());
    }

    //Memory commands

    public void dataReadMemoryBytes(String address, int count) throws IOException {
        if (address == null || address.isEmpty()) {
            throw new IllegalArgumentException("Address must be specified");
        }
        send("-data-read-memory-bytes " + address + " " + count);
    }

    public void dataReadMemoryBytesOffset(String address, int offset, int count)
            throws IOException {
        if (address == null || address.isEmpty()) {
            throw new IllegalArgumentException("Address must be specified");
        }
        send("-data-read-memory-bytes -o " + offset + " " + address + " " + count);
    }

    public void dataWriteMemoryBytes(String address, String hexBytes) throws IOException {
        if (address == null || address.isEmpty() || hexBytes == null || hexBytes.isEmpty()) {
            throw new IllegalArgumentException("Both address and hexBytes must be specified");
        }
        send("-data-write-memory-bytes " + address + " \"" + hexBytes + "\"");
    }

    public void dataWriteMemoryBytes(String address, String hexBytes, int count)
            throws IOException {
        if (address == null || address.isEmpty() || hexBytes == null || hexBytes.isEmpty()) {
            throw new IllegalArgumentException("Both address and hexBytes must be specified");
        }
        send("-data-write-memory-bytes " + address + " \"" + hexBytes + "\" " + count);
    }

    //Tracepoints commands

    public void traceFindNone() throws IOException {
        send("-trace-find none");
    }

    public void traceFindFrameNumber(int frame) throws IOException {
        send("-trace-find frame-number " + frame);
    }

    public void traceFindTracepointNumber(int tp) throws IOException {
        send("-trace-find tracepoint-number " + tp);
    }

    public void traceFindPc(String address) throws IOException {
        if (address == null || address.isEmpty()) {
            throw new IllegalArgumentException("Address must be specified");
        }
        send("-trace-find pc " + address);
    }

    public void traceFindPcInsideRange(String start, String end) throws IOException {
        if (start == null || start.isEmpty() || end == null || end.isEmpty()) {
            throw new IllegalArgumentException("Both start and end addresses must be specified");
        }
        send("-trace-find pc-inside-range " + start + " " + end);
    }

    public void traceFindPcOutsideRange(String start, String end) throws IOException {
        if (start == null || start.isEmpty() || end == null || end.isEmpty()) {
            throw new IllegalArgumentException("Both start and end addresses must be specified");
        }
        send("-trace-find pc-outside-range " + start + " " + end);
    }

    public void traceFindLine(String location) throws IOException {
        if (location == null || location.isEmpty()) {
            throw new IllegalArgumentException("Location must be specified");
        }
        send("-trace-find line " + location);
    }

    public void traceDefineVariable(String name, String value) throws IOException {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Variable name must be specified");
        }
        if (value == null || value.isEmpty()) {
            send("-trace-define-variable " + name);
        }
        else {
            send("-trace-define-variable " + name + " " + value);
        }
    }

    public void traceListVariables() throws IOException {
        send("-trace-list-variables");
    }

    public void traceFrameCollected() throws IOException {
        send("-trace-frame-collected");
    }

    public void traceFrameCollectedVarPrint(int mode) throws IOException {
        send("-trace-frame-collected --var-print-values " + mode);
    }

    public void traceFrameCollectedCompPrint(int mode) throws IOException {
        send("-trace-frame-collected --comp-print-values " + mode);
    }

    public void traceFrameCollectedRegisters(char format) throws IOException {
        send("-trace-frame-collected --registers-format " + format);
    }

    public void traceFrameCollectedMemoryContents() throws IOException {
        send("-trace-frame-collected --memory-contents");
    }

    public void traceFrameCollectedFull(int varMode, int compMode, char regFormat)
            throws IOException {
        send("-trace-frame-collected --var-print-values " + varMode +
            " --comp-print-values " + compMode +
            " --registers-format " + regFormat +
            " --memory-contents");
    }

    public void traceStart() throws IOException {
        send("-trace-start");
    }

    public void traceStop() throws IOException {
        send("-trace-stop");
    }

    public void traceStatus() throws IOException {
        send("-trace-status");
    }

    public void traceSave(String filename, boolean remote, boolean ctf) throws IOException {
        if (filename == null || filename.isEmpty()) {
            throw new IllegalArgumentException("Filename must be specified");
        }

        StringBuilder sb = new StringBuilder("-trace-save");
        if (remote)
            sb.append(" -r");
        if (ctf)
            sb.append(" -ctf");
        sb.append(" ").append(filename);

        send(sb.toString());
    }

    //Symbol commands

    public void symbolInfoFunctions() throws IOException {
        send("-symbol-info-functions");
    }

    public void symbolInfoFunctions(String nameRegex, String typeRegex, int limit,
            boolean includeNonDebug) throws IOException {
        StringBuilder cmd = new StringBuilder("-symbol-info-functions");
        if (includeNonDebug)
            cmd.append(" --include-nondebug");
        if (nameRegex != null && !nameRegex.isEmpty())
            cmd.append(" --name ").append(nameRegex);
        if (typeRegex != null && !typeRegex.isEmpty())
            cmd.append(" --type ").append(typeRegex);
        if (limit > 0)
            cmd.append(" --max-results ").append(limit);
        send(cmd.toString());
    }

    public void symbolInfoModuleFunctions() throws IOException {
        send("-symbol-info-module-functions");
    }

    public void symbolInfoModuleFunctions(String module, String name, String type)
            throws IOException {
        StringBuilder cmd = new StringBuilder("-symbol-info-module-functions");
        if (module != null && !module.isEmpty())
            cmd.append(" --module ").append(module);
        if (name != null && !name.isEmpty())
            cmd.append(" --name ").append(name);
        if (type != null && !type.isEmpty())
            cmd.append(" --type ").append(type);
        send(cmd.toString());
    }

    public void symbolInfoModuleVariables() throws IOException {
        send("-symbol-info-module-variables");
    }

    public void symbolInfoModuleVariables(String module, String name, String type)
            throws IOException {
        StringBuilder cmd = new StringBuilder("-symbol-info-module-variables");
        if (module != null && !module.isEmpty())
            cmd.append(" --module ").append(module);
        if (name != null && !name.isEmpty())
            cmd.append(" --name ").append(name);
        if (type != null && !type.isEmpty())
            cmd.append(" --type ").append(type);
        send(cmd.toString());
    }

    public void symbolInfoModules() throws IOException {
        send("-symbol-info-modules");
    }

    public void symbolInfoModules(String name, int limit) throws IOException {
        StringBuilder cmd = new StringBuilder("-symbol-info-modules");
        if (name != null && !name.isEmpty())
            cmd.append(" --name ").append(name);
        if (limit > 0)
            cmd.append(" --max-results ").append(limit);
        send(cmd.toString());
    }

    public void symbolInfoTypes() throws IOException {
        send("-symbol-info-types");
    }

    public void symbolInfoTypes(String name, int limit) throws IOException {
        StringBuilder cmd = new StringBuilder("-symbol-info-types");
        if (name != null && !name.isEmpty())
            cmd.append(" --name ").append(name);
        if (limit > 0)
            cmd.append(" --max-results ").append(limit);
        send(cmd.toString());
    }

    public void symbolInfoVariables() throws IOException {
        send("-symbol-info-variables");
    }

    public void symbolInfoVariables(String name, String type, int limit, boolean includeNonDebug)
            throws IOException {
        StringBuilder cmd = new StringBuilder("-symbol-info-variables");
        if (includeNonDebug)
            cmd.append(" --include-nondebug");
        if (name != null && !name.isEmpty())
            cmd.append(" --name ").append(name);
        if (type != null && !type.isEmpty())
            cmd.append(" --type ").append(type);
        if (limit > 0)
            cmd.append(" --max-results ").append(limit);
        send(cmd.toString());
    }

    public void symbolListLines(String filename) throws IOException {
        if (filename == null || filename.isEmpty()) {
            throw new IllegalArgumentException("Filename must be specified");
        }
        send("-symbol-list-lines " + filename);
    }

    //File commands

    public void fileExecAndSymbols(String file) throws IOException {
        if (file == null || file.isEmpty()) {
            send("-file-exec-and-symbols");
        }
        else {
            send("-file-exec-and-symbols " + file);
        }
    }

    public void fileExecFile(String file) throws IOException {
        if (file == null || file.isEmpty()) {
            send("-file-exec-file");
        }
        else {
            send("-file-exec-file " + file);
        }
    }

    public void fileListExecSourceFile() throws IOException {
        send("-file-list-exec-source-file");
    }

    public void fileListExecSourceFiles() throws IOException {
        send("-file-list-exec-source-files");
    }

    public void fileListExecSourceFiles(String regexp) throws IOException {
        if (regexp == null || regexp.isEmpty()) {
            send("-file-list-exec-source-files");
        }
        else {
            send("-file-list-exec-source-files -- " + regexp);
        }
    }

    public void fileListExecSourceFiles(boolean groupByObjfile, boolean dirname, boolean basename,
            String regexp) throws IOException {
        StringBuilder cmd = new StringBuilder("-file-list-exec-source-files");
        if (groupByObjfile)
            cmd.append(" --group-by-objfile");
        if (dirname)
            cmd.append(" --dirname");
        if (basename)
            cmd.append(" --basename");
        if (regexp != null && !regexp.isEmpty())
            cmd.append(" -- ").append(regexp);
        send(cmd.toString());
    }

    public void fileListSharedLibraries() throws IOException {
        send("-file-list-shared-libraries");
    }

    public void fileListSharedLibraries(String regexp) throws IOException {
        if (regexp == null || regexp.isEmpty()) {
            send("-file-list-shared-libraries");
        }
        else {
            send("-file-list-shared-libraries " + regexp);
        }
    }

    public void fileSymbolFile(String file) throws IOException {
        if (file == null || file.isEmpty()) {
            send("-file-symbol-file");
        }
        else {
            send("-file-symbol-file " + file);
        }
    }

    //Target commands

    public void targetAttach(String pidOrGidOrFile) throws IOException {
        if (pidOrGidOrFile == null || pidOrGidOrFile.isEmpty()) {
            throw new IllegalArgumentException("pid, gid, or file must be specified");
        }
        send("-target-attach " + pidOrGidOrFile);
    }

    public void targetDetach() throws IOException {
        send("-target-detach");
    }

    public void targetDetach(String pidOrGid) throws IOException {
        if (pidOrGid == null || pidOrGid.isEmpty()) {
            send("-target-detach");
        }
        else {
            send("-target-detach " + pidOrGid);
        }
    }

    public void targetDisconnect() throws IOException {
        send("-target-disconnect");
    }

    public void targetDownload() throws IOException {
        send("-target-download");
    }

    public void targetFlashErase() throws IOException {
        send("-target-flash-erase");
    }

    public void targetSelect(String type, String parameters) throws IOException {
        if (type == null || type.isEmpty()) {
            throw new IllegalArgumentException("Target type must be specified");
        }
        if (parameters == null || parameters.isEmpty()) {
            send("-target-select " + type);
        }
        else {
            send("-target-select " + type + " " + parameters);
        }
    }

    //File transfer commands

    public void targetFilePut(String hostFile, String targetFile) throws IOException {
        if (hostFile == null || hostFile.isEmpty() || targetFile == null || targetFile.isEmpty()) {
            throw new IllegalArgumentException("Both hostFile and targetFile must be specified");
        }
        send("-target-file-put " + hostFile + " " + targetFile);
    }

    public void targetFileGet(String targetFile, String hostFile) throws IOException {
        if (targetFile == null || targetFile.isEmpty() || hostFile == null || hostFile.isEmpty()) {
            throw new IllegalArgumentException("Both targetFile and hostFile must be specified");
        }
        send("-target-file-get " + targetFile + " " + hostFile);
    }

    public void targetFileDelete(String targetFile) throws IOException {
        if (targetFile == null || targetFile.isEmpty()) {
            throw new IllegalArgumentException("targetFile must be specified");
        }
        send("-target-file-delete " + targetFile);
    }

    //Ada exception commands

    public void infoAdaExceptions() throws IOException {
        send("-info-ada-exceptions");
    }

    public void infoAdaExceptions(String regexp) throws IOException {
        if (regexp == null || regexp.isEmpty()) {
            send("-info-ada-exceptions");
        }
        else {
            send("-info-ada-exceptions " + regexp);
        }
    }

    //GDB support commands

    public void infoGdbMiCommand(String commandName) throws IOException {
        if (commandName == null || commandName.isEmpty()) {
            throw new IllegalArgumentException("Command name must be specified");
        }

        String cmd = commandName.startsWith("-") ? commandName : "-" + commandName;
        send("-info-gdb-mi-command " + cmd);
    }

    public void listFeatures() throws IOException {
        send("-list-features");
    }

    public void listTargetFeatures() throws IOException {
        send("-list-target-features");
    }

    //GDB miscellaneous commands

    public void gdbExit() throws IOException {
        send("-gdb-exit");
    }

    public void gdbSet(String variable, String value) throws IOException {
        if (variable == null || variable.isEmpty()) {
            throw new IllegalArgumentException("Variable name must be specified");
        }
        if (value == null)
            value = "";
        send("-gdb-set " + variable + "=" + value);
    }

    public void gdbShow(String variable) throws IOException {
        if (variable == null || variable.isEmpty()) {
            throw new IllegalArgumentException("Variable name must be specified");
        }
        send("-gdb-show " + variable);
    }

    public void gdbVersion() throws IOException {
        send("-gdb-version");
    }

    public void listThreadGroups(boolean available, int recurse, String... groups)
            throws IOException {
        StringBuilder cmd = new StringBuilder("-list-thread-groups");
        if (available)
            cmd.append(" --available");
        if (recurse > 0)
            cmd.append(" --recurse ").append(recurse);
        if (groups != null) {
            for (String g : groups) {
                if (g != null && !g.isEmpty())
                    cmd.append(" ").append(g);
            }
        }
        send(cmd.toString());
    }

    public void infoOs(String type) throws IOException {
        if (type == null || type.isEmpty()) {
            send("-info-os");
        }
        else {
            send("-info-os " + type);
        }
    }

    public void interpreterExec(String interpreter, String command) throws IOException {
        if (interpreter == null || interpreter.isEmpty()) {
            throw new IllegalArgumentException("Interpreter must be specified");
        }
        if (command == null)
            command = "";
        send("-interpreter-exec " + interpreter + " \"" + command + "\"");
    }

    public void enableTimings(Boolean enable) throws IOException {
        send("-enable-timings" + (enable == null ? "" : (enable ? " yes" : " no")));
    }

    public void complete(String command) throws IOException {
        if (command == null)
            command = "";
        send("-complete \"" + command + "\"");
    }

    //General

    public void exit() throws IOException {
        send("-gdb-exit");
        shutdown();
    }

    //Main function of sending commands from user to gdb

    public void send(String cmd) throws IOException {
        gdbIn.write(cmd);
        gdbIn.newLine();
        gdbIn.flush();
        writeOutput("[user] " + cmd);
    }

    //Function to parse PC (counter of where the program stopped) from *stopped and notify stopListener

    private static long parsePcFromStopped(String line) {
        Pattern p = Pattern.compile("addr=\"(0x[0-9a-fA-F]+)\"");
        Matcher m = p.matcher(line);

        if (m.find()) {
            return Long.decode(m.group(1));
        }

        throw new IllegalStateException("PC not found in stopped record: " + line);
    }

    public void setStopListener(GdbStopListener l) {
        this.stopListener = l;
    }

    //Main function to read output from gdb, parse it and notify outputListener

    private void readGdbOutput() {
        try {
            String line;
            while ((line = gdbOut.readLine()) != null) {
                handleGdbEvent(line);
                if (line.startsWith("*stopped")) {
                    long pc = parsePcFromStopped(line);
                    if (stopListener != null) {
                        stopListener.onStopped(pc);
                    }
                }

            }
        }
        catch (IOException e) {
            writeOutput("GDB output stopped");
        }
    }

    public void setOutputListener(GDBOutputListener listener) {
        this.outputListener = listener;
    }

    private void handleGdbEvent(String line) {
        String parsedOutput = outputParser.parseOutput(line);
        writeOutput("[out] " + parsedOutput);
    }

    private void shutdown() {
        if (gdb != null)
            gdb.destroy();
        ioThreads.shutdownNow();
    }

    //Reading memory or register (TRACKING)

    private synchronized String readResultRecord() throws IOException {
        StringBuilder sb = new StringBuilder();
        String line;

        while ((line = gdbOut.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty())
                continue;

            sb.append(line);

            if (line.startsWith("^done") || line.startsWith("^error")) {
                break;
            }
        }

        if (sb.length() == 0) {
            throw new IOException("No result record");
        }

        return sb.toString();
    }

    public BigInteger readRegister(String regName) {
        try {
            send("-data-evaluate-expression $" + regName);

            String reply = readResultRecord();

            int idx = reply.indexOf("value=\"");
            if (idx != -1) {
                int start = idx + 7;
                int end = reply.indexOf("\"", start);
                String hex = reply.substring(start, end);
                return new BigInteger(hex.replace("0x", ""), 16);
            }
            else {
                throw new RuntimeException("Failed to read register " + regName + ": " + reply);
            }

        }
        catch (IOException e) {
            throw new RuntimeException("IO error reading register " + regName, e);
        }
    }

    public byte[] readMemory(long addr, int size) {
        try {
            send("-data-read-memory-bytes 0x" + Long.toHexString(addr) + " " + size);

            String reply = readResultRecord();

            int idx = reply.indexOf("contents=\"");
            if (idx != -1) {
                int start = idx + 10;
                int end = reply.indexOf("\"", start);
                String hex = reply.substring(start, end);

                byte[] result = new byte[hex.length() / 2];
                for (int i = 0; i < result.length; i++) {
                    result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
                }
                return result;
            }
            else {
                throw new RuntimeException(
                    "Failed to read memory at 0x" + Long.toHexString(addr) + ": " + reply);
            }

        }
        catch (IOException e) {
            throw new RuntimeException(
                "IO error reading memory at 0x" + Long.toHexString(addr), e);
        }
    }

}
