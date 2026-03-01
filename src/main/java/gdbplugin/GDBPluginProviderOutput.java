package gdbplugin;

import docking.ComponentProvider;
import gdbplugin.GDBPluginController;
import ghidra.framework.plugintool.Plugin;

import javax.swing.*;
import java.awt.*;

public class GDBPluginProviderOutput extends ComponentProvider {

    private JPanel panel;
    private JTextArea outputArea;
    private GDBPluginController controller;

    public GDBPluginProviderOutput(Plugin plugin, String owner, GDBPluginController controller) {
        super(plugin.getTool(), "GDBPlugin Output", owner);
        this.controller = controller;

        panel = new JPanel(new BorderLayout());
        outputArea = new JTextArea(20, 80);
        outputArea.setEditable(false);
        outputArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

        JScrollPane scrollPane = new JScrollPane(outputArea);
        panel.add(scrollPane, BorderLayout.CENTER);

        controller.setOutputListener(this::appendOutput);
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    private void appendOutput(String line) {
        SwingUtilities.invokeLater(() -> {
            outputArea.append(line + "\n");
            outputArea.setCaretPosition(outputArea.getDocument().getLength());
        });
    }
}
