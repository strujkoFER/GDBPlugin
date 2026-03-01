package gdbplugin;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.DEBUGGER,
	shortDescription = "Control GDB",
	description = "Plugin to control GDB and track variables"
)
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
		});
	}

	@Override
	public void init() {
		setActiveProgram();
		super.init();
		initProviders();
	}

	public void setActiveProgram() {
		currentProgram =
			tool.getService(ghidra.app.services.ProgramManager.class).getCurrentProgram();
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

}
