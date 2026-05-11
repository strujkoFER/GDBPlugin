package gdbplugin;

import java.io.IOException;

import docking.action.builder.ActionBuilder;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.Msg;

@PluginInfo(status = PluginStatus.STABLE, packageName = ExamplesPluginPackage.NAME, category = PluginCategoryNames.DEBUGGER, shortDescription = "Control GDB", description = "Plugin to control GDB and track variables")
public class GDBPluginPlugin extends ProgramPlugin {

	private GDBPluginController gdbController;
	private GDBPluginProviderInput providerInput;
	private GDBPluginProviderOutput providerOutput;

	public GDBPluginPlugin(PluginTool tool) {
		super(tool);

		gdbController = new GDBPluginController();

		gdbController.setStopListener(pc -> {
			// pc is the program counter where the program stopped
			// TODO add call for tracking of variables here

			gdbController.listValuesTrackedVariables(pc);
		});
	}

	@Override
	public void init() {
		setActiveProgram();
		super.init();
		initProviders();
		createActions();
	}

	public void setActiveProgram() {
		currentProgram = tool.getService(ghidra.app.services.ProgramManager.class).getCurrentProgram();
	}

	public void startGDBPlugin() {
		setActiveProgram();

		if (currentProgram == null) {
			Msg.showError(this, null, "GDB Plugin", "No program is currently open!");
		}

		new Thread(() -> gdbController.startEverything(currentProgram, 1234), "GDBStarterThread")
				.start();
	}

	private void initProviders() {

		providerInput = new GDBPluginProviderInput(this, "David", gdbController);
		providerOutput = new GDBPluginProviderOutput(this, "David", gdbController);

		if (tool.getComponentProvider("GDBPlugin Input") != null) {
			tool.removeComponentProvider(providerInput);
		}
		if (tool.getComponentProvider("GDBPlugin Output") != null) {
			tool.removeComponentProvider(providerOutput);
		}

		tool.addComponentProvider(providerInput, true);
		tool.addComponentProvider(providerOutput, true);
	}

	private boolean isVariableUnderCursor(DecompilerActionContext context) {
		ClangToken token = context.getTokenAtCursor();
		if (token == null) {
			return false;
		}

		HighSymbol symbol = token.getHighSymbol(context.getHighFunction());
		if (symbol == null) {
			return false;
		}

		HighVariable highVariable = symbol.getHighVariable();
		return highVariable != null;
	}

	private void createActions() {

		String actionName = "Track variable";
		new ActionBuilder(actionName, getName())
				.withContext(DecompilerActionContext.class)
				.enabledWhen(this::isVariableUnderCursor)
				.onAction(context -> gdbController.trackVariable((DecompilerActionContext) context))
				.popupMenuPath("Tracking", actionName)
				.popupMenuGroup("Tracking")
				.buildAndInstall(tool);

		actionName = "Delete variable";
		new ActionBuilder(actionName, getName())
				.withContext(DecompilerActionContext.class)
				.enabledWhen(this::isVariableUnderCursor)
				.onAction(context -> gdbController.deleteTrackedVariable((DecompilerActionContext) context))
				.popupMenuPath("Tracking", actionName)
				.popupMenuGroup("Tracking")
				.buildAndInstall(tool);

		actionName = "Show all tracked variables";
		new ActionBuilder(actionName, getName())
				.withContext(DecompilerActionContext.class)
				.onAction(context -> gdbController.listTrackedVariables())
				.popupMenuPath("Tracking", actionName)
				.popupMenuGroup("Tracking")
				.buildAndInstall(tool);

		actionName = "Set breakpoint";
		new ActionBuilder(actionName, getName())
				.withContext(DecompilerActionContext.class)
				.onAction(context -> {
					Address addr = context.getAddress();
					if (addr == null) {
						gdbController.writeOutput("Error with address while placing breakpoint");
						return;
					}
					String location = "0x" + Long.toHexString(addr.getOffset());
					try {
						gdbController.setBreakpoint(
								location,
								false,
								false,
								false,
								null,
								null);
					} catch (IOException e) {
						gdbController.writeOutput("Error placing breakpoint");
					}
				})
				.popupMenuPath("Breakpoints", actionName)
				.popupMenuGroup("Breakpoints")
				.buildAndInstall(tool);
	}

}
