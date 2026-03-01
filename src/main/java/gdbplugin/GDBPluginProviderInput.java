package gdbplugin;

import docking.ComponentProvider;
import gdbplugin.GDBPluginController;
import gdbplugin.ButtonsData;
import ghidra.framework.plugintool.Plugin;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class GDBPluginProviderInput extends ComponentProvider {

    private static final Color BACKGROUND_COLOR = new Color(0xFFE1FF);
    private static final Color COMMON_COLOR = new Color(0xE4B1F0);

    private JPanel panel;
    private JScrollPane scrollPane;
    private GDBPluginController controller;
    private java.util.List<JPanel> allCommandPanels = new java.util.ArrayList<>();
    private JTextField searchField;

    public GDBPluginProviderInput(Plugin plugin, String owner, GDBPluginController controller) {
        super(plugin.getTool(), "GDBPlugin Input", owner);
        this.controller = controller;

        panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(BACKGROUND_COLOR);

        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        searchPanel.setBackground(BACKGROUND_COLOR);
        searchPanel.setBorder(BorderFactory.createTitledBorder("Search Commands"));
        searchField = new JTextField(20);
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                filterCommands();
            }

            public void removeUpdate(DocumentEvent e) {
                filterCommands();
            }

            public void changedUpdate(DocumentEvent e) {
                filterCommands();
            }
        });
        JLabel searchLabel = new JLabel("Filter: ");
        searchPanel.add(searchLabel);
        searchPanel.add(searchField);
        searchPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 60));
        searchPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        panel.add(searchPanel);

        JButton runGDBButton = new JButton("Run GDB");
        runGDBButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        runGDBButton.addActionListener(e -> {
            try {
                if (plugin instanceof GDBPluginPlugin gdbPlugin) {
                    gdbPlugin.startGDBPlugin();
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "Error: " + ex.getMessage());
                ex.printStackTrace();
            }
        });

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        topPanel.setBackground(BACKGROUND_COLOR);
        topPanel.add(runGDBButton);
        topPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 50));
        topPanel.setAlignmentX(Component.CENTER_ALIGNMENT);

        panel.add(topPanel);
        panel.revalidate();
        panel.repaint();

        JPanel resetPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        resetPanel.setBackground(BACKGROUND_COLOR);
        resetPanel.setBorder(BorderFactory.createTitledBorder("Reset / Restart"));

        JButton fullResetButton = new JButton("Full Reset");
        fullResetButton.addActionListener(e -> {
            try {
                if (plugin instanceof GDBPluginPlugin gdbPlugin) {
                    controller.resetEverything();
                    gdbPlugin.startGDBPlugin();
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "Error: " + ex.getMessage());
                ex.printStackTrace();
            }
        });
        resetPanel.add(fullResetButton);

        JButton restartProgramButton = new JButton("Restart Program");
        restartProgramButton.addActionListener(e -> {
            try {
                controller.restartProgram();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "Error: " + ex.getMessage());
                ex.printStackTrace();
            }
        });
        resetPanel.add(restartProgramButton);

        resetPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 60));
        resetPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        panel.add(resetPanel);
        panel.revalidate();
        panel.repaint();

        buildCommandPanels();

        scrollPane = new JScrollPane(panel,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.getViewport().setBackground(BACKGROUND_COLOR);

        scrollPane.setPreferredSize(new Dimension(400, 400));

        setVisible(true);
    }

    @Override
    public JComponent getComponent() {
        return scrollPane;
    }

    private void buildCommandPanels() {
        JPanel commonPanel = new JPanel();
        commonPanel.setLayout(new BoxLayout(commonPanel, BoxLayout.Y_AXIS));
        commonPanel.setBackground(COMMON_COLOR);
        commonPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(COMMON_COLOR, 2), "Common Commands"));

        for (String methodName : ButtonsData.COMMON_METHODS) {
            try {
                Method method = getMethodByName(methodName);
                if (method != null) {
                    JPanel cmdPanel = buildCommandPanel(method);
                    commonPanel.add(cmdPanel);
                    allCommandPanels.add(cmdPanel);
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "Error: " + ex.getMessage());
                ex.printStackTrace();
            }
        }

        panel.add(commonPanel);

        Set<String> commonSet = new HashSet<>(Arrays.asList(ButtonsData.COMMON_METHODS));
        List<String> remainingMethodNames = new ArrayList<>();
        for (String methodName : ButtonsData.PARAM_NAME_MAP.keySet()) {
            if (!commonSet.contains(methodName)) {
                remainingMethodNames.add(methodName);
            }
        }
        remainingMethodNames.sort(String.CASE_INSENSITIVE_ORDER);

        for (String methodName : remainingMethodNames) {
            try {
                Method method = getMethodByName(methodName);
                if (method != null) {
                    JPanel cmdPanel = buildCommandPanel(method);
                    panel.add(cmdPanel);
                    allCommandPanels.add(cmdPanel);
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "Error: " + ex.getMessage());
                ex.printStackTrace();
            }
        }
    }

    private Method getMethodByName(String methodName) {
        for (Method method : GDBPluginController.class.getDeclaredMethods()) {
            if (method.getName().equals(methodName) && Modifier.isPublic(method.getModifiers())) {
                return method;
            }
        }
        return null;
    }

    private void filterCommands() {
        String searchText = searchField.getText().toLowerCase().trim();

        for (JPanel cmdPanel : allCommandPanels) {
            if (searchText.isEmpty()) {
                cmdPanel.setVisible(true);
            } else {
                String title = ((javax.swing.border.TitledBorder) cmdPanel.getBorder()).getTitle();
                cmdPanel.setVisible(title.toLowerCase().contains(searchText));
            }
        }

        panel.revalidate();
        panel.repaint();
    }

    private JPanel buildCommandPanel(Method method) {
        JPanel cmdPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        cmdPanel.setBackground(BACKGROUND_COLOR);
        cmdPanel.setBorder(BorderFactory.createTitledBorder(method.getName()));

        Parameter[] params = method.getParameters();
        Map<Parameter, JComponent> paramComponents = new HashMap<>();
        Map<Parameter, Boolean> paramRequired = new HashMap<>();
        String[] names = ButtonsData.PARAM_NAME_MAP.get(method.getName());
        boolean[] required = ButtonsData.REQUIRED_PARAMS.get(method.getName());

        for (int i = 0; i < params.length; i++) {
            Parameter param = params[i];
            Class<?> type = param.getType();

            String paramName = (names != null && i < names.length) ? names[i] : param.getName();
            boolean isRequired = (required != null && i < required.length) ? required[i] : true;

            String labelText = paramName + (isRequired ? " *" : "");
            JLabel label = new JLabel(labelText + ":");

            JComponent inputComponent;
            if (type == boolean.class || type == Boolean.class) {
                inputComponent = new JCheckBox();
            } else {
                inputComponent = new JTextField(10);
            }

            cmdPanel.add(label);
            cmdPanel.add(inputComponent);
            paramComponents.put(param, inputComponent);
            paramRequired.put(param, isRequired);
        }

        JButton btn = new JButton(method.getName());
        btn.setEnabled(areRequiredParamsSatisfied(paramComponents, paramRequired));

        DocumentListener docListener = new DocumentListener() {
            void update() {
                btn.setEnabled(areRequiredParamsSatisfied(paramComponents, paramRequired));
            }

            public void insertUpdate(DocumentEvent e) {
                update();
            }

            public void removeUpdate(DocumentEvent e) {
                update();
            }

            public void changedUpdate(DocumentEvent e) {
                update();
            }
        };

        for (JComponent comp : paramComponents.values()) {
            if (comp instanceof JTextField tf) {
                tf.getDocument().addDocumentListener(docListener);
            }
        }

        btn.addActionListener(e -> {
            try {
                Object[] args = new Object[params.length];
                int i = 0;
                for (Parameter param : params) {
                    JComponent comp = paramComponents.get(param);
                    Class<?> type = param.getType();

                    if (comp instanceof JTextField tf) {
                        String value = tf.getText().trim();
                        if (value.isEmpty()) {
                            args[i++] = null;
                        } else {
                            args[i++] = convertStringToType(value, type);
                        }
                    } else if (comp instanceof JCheckBox cb) {
                        args[i++] = cb.isSelected();
                    }
                }

                Object result = method.invoke(controller, args);
                if (result != null) {
                    JOptionPane.showMessageDialog(panel, "Result: " + result.toString());
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "Error: " + ex.getMessage());
                ex.printStackTrace();
            }
        });

        cmdPanel.add(btn);
        return cmdPanel;
    }

    private Object convertStringToType(String value, Class<?> type) {
        if (type == String.class)
            return value;
        if (type == int.class || type == Integer.class)
            return Integer.parseInt(value);
        if (type == long.class || type == Long.class)
            return Long.decode(value);
        if (type == boolean.class || type == Boolean.class)
            return Boolean.parseBoolean(value);
        return value;
    }

    private boolean areRequiredParamsSatisfied(Map<Parameter, JComponent> paramComponents,
            Map<Parameter, Boolean> paramRequired) {
        for (Map.Entry<Parameter, JComponent> entry : paramComponents.entrySet()) {
            Parameter param = entry.getKey();
            JComponent comp = entry.getValue();
            boolean isRequired = Boolean.TRUE.equals(paramRequired.get(param));
            if (isRequired && comp instanceof JTextField tf) {
                if (tf.getText().trim().isEmpty()) {
                    return false;
                }
            }
        }
        return true;
    }

}
