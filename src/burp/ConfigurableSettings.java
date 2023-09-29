package burp;

import javax.swing.*;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import javax.swing.text.NumberFormatter;
import java.awt.*;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

class ConfigMenu implements Runnable, MenuListener, IExtensionStateListener{
    private JMenu menuButton;
    private JMenuItem menuItem;

    ConfigMenu() {
        Utilities.callbacks.registerExtensionStateListener(this);
    }

    public void run()
    {
        try {
            menuButton = new JMenu(Utilities.name);
            menuItem = new JMenuItem(new AbstractAction("Settings") {
                public void actionPerformed(ActionEvent ae) {
                    SwingUtilities.invokeLater(new Runnable() {
                        public void run() {
                            Utilities.globalSettings.showSettings();
                        }
                    });
                }
            });

            menuButton.add(menuItem);
            JMenuBar burpMenuBar = Utilities.getBurpFrame().getJMenuBar();
            burpMenuBar.add(menuButton);
            burpMenuBar.repaint();
        } catch (NullPointerException e){
            Utilities.log("Couldn't find Burp menu bar - probably running headless/enterprise");
        }
    }

    public void menuSelected(MenuEvent e) {
//        SwingUtilities.invokeLater(new Runnable() {
//            public void run(){
//                Utilities.globalSettings.showSettings();
//            }
//        });
    }

    public void menuDeselected(MenuEvent e) { }

    public void menuCanceled(MenuEvent e) { }

    public void extensionUnloaded() {
        try {
            JMenuBar jMenuBar = Utilities.getBurpFrame().getJMenuBar();
            jMenuBar.remove(menuButton);
            jMenuBar.repaint();
        } catch (NullPointerException e) {

        }
    }
}


interface ConfigListener {
    void valueUpdated(String value);
}

class Setting {
    String value = "";

}

class ConfigurableSettings {
    static private LinkedHashMap<String, String> settings = new LinkedHashMap<>();
    static private LinkedHashMap<String, String> settingDescriptions = new LinkedHashMap<>();
    static private LinkedHashMap<String, String> defaultSettings = new LinkedHashMap<>();
    private NumberFormatter onlyInt;

    private HashMap<String, ConfigListener> callbacks = new HashMap<>();

    public void registerListener(String key, ConfigListener listener) {
        callbacks.put(key, listener);
    }

    void registerSetting(String key, Object value) {
        registerSetting(key, value, null);
    }

    void registerSetting(String key, Object value, String description) {
        if (description != null && !settingDescriptions.containsKey(key)) {
            settingDescriptions.put(key, description);
        }

        if (settings.containsKey(key)) {
            return;
        }
        defaultSettings.put(key, encode(value));

        String oldValue = Utilities.callbacks.loadExtensionSetting(key);
        if (oldValue != null) {
            putRaw(key, oldValue);
            return;
        }

        putRaw(key, encode(value));
    }

    ConfigurableSettings(HashMap<String, Object> inputSettings) {

        for (String key: inputSettings.keySet()) {
            registerSetting(key, inputSettings.get(key));
        }


        for(String key: settings.keySet()) {
            //Utilities.callbacks.saveExtensionSetting(key, null); // purge saved settings
            String value = Utilities.callbacks.loadExtensionSetting(key);
            if (Utilities.callbacks.loadExtensionSetting(key) != null) {
                putRaw(key, value);
            }
        }

        NumberFormat format = NumberFormat.getInstance();
        onlyInt = new NumberFormatter(format);
        onlyInt.setValueClass(Integer.class);
        onlyInt.setMinimum(-1);
        onlyInt.setMaximum(Integer.MAX_VALUE);
        onlyInt.setAllowsInvalid(false);
    }

    public void setDefaultSettings() {
        for (String key: settings.keySet()) {
            putRaw(key, defaultSettings.get(key));
        }
    }

    private ConfigurableSettings(ConfigurableSettings base) {
        settings = new LinkedHashMap<>(base.settings);
        onlyInt = base.onlyInt;
    }

    void printSettings() {
        for(String key: settings.keySet()) {
            Utilities.out(key + ": "+settings.get(key));
        }
    }

    static JFrame getBurpFrame()
    {
        for(Frame f : Frame.getFrames())
        {
            if(f.isVisible() && f.getTitle().startsWith(("Burp Suite")))
            {
                return (JFrame) f;
            }
        }
        return null;
    }

    private String encode(Object value) {
        String encoded;
        if (value instanceof Boolean) {
            encoded = String.valueOf(value);
        }
        else if (value instanceof Integer) {
            encoded = String.valueOf(value);
        }
        else {
            encoded = "\"" + ((String) value).replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
        }
        return encoded;
    }

    private void putRaw(String key, String value) {
        settings.put(key, value);
        ConfigListener callback = callbacks.getOrDefault(key, null);
        if (callback != null) {
            callback.valueUpdated(value);
        }
    }

    private void put(String key, Object value) {
        putRaw(key, encode(value));
    }

    String getString(String key) {
        String decoded = settings.get(key);
        decoded = decoded.substring(1, decoded.length()-1).replace("\\\"", "\"").replace("\\\\", "\\");
        return decoded;
    }

    int getInt(String key) {
        return Integer.parseInt(settings.get(key));
    }

    boolean getBoolean(String key) {
        String val = settings.get(key);
        if ("true".equals(val)) {
            return true;
        }
        else if ("false".equals(val)){
            return false;
        }
        throw new RuntimeException();
    }

    private String getType(String key) {
        String val = settings.get(key);
        if (val.equals("true") || val.equals("false")) {
            return "boolean";
        }
        else if (val.startsWith("\"")) {
            return "string";
        }
        else {
            return "number";
        }
    }

    ConfigurableSettings showSettings() {
        return showSettings(new ArrayList<>(settings.keySet()));
    }

    ConfigurableSettings showSettings(ArrayList<String> settingsToShow) {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(0, 6));
        // panel.setSize(800, 800);
        JScrollPane scrollPane = new JScrollPane(panel);
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        int requiredHeight = (settingsToShow.size() / 3) * 30;
        int targetWidth = Math.min(1400, screenSize.width-300);
        int targetHeight = Math.min(requiredHeight+100, screenSize.height-300);
        scrollPane.setPreferredSize(new Dimension(targetWidth, targetHeight));
        
        //scrollPane.setPreferredSize(new Dimension(targetWidth, targetHeight));
        //scrollPane.setMaximumSize(new Dimension(screenSize.width-500, screenSize.height-500));
        //scrollPane.setPreferredSize(new Dimension(700,300));
        //panel.add(scrollPane);


        HashMap<String, Object> configured = new HashMap<>();
        JButton buttonResetSettings = new JButton("Reset Visible Settings");

        for(String key: settingsToShow) {
            String type = getType(key);
            JLabel label = new JLabel("\n"+key+": ");

            label.setToolTipText(settingDescriptions.getOrDefault(key, "No description available"));

            if (!settings.get(key).equals(defaultSettings.get(key))) {
                label.setForeground(Color.magenta);
            }
            panel.add(label);

            if (type.equals("boolean")) {
                JCheckBox box = new JCheckBox();
                box.setSelected(getBoolean(key));
                panel.add(box);
                configured.put(key, box);
            }
            else if (type.equals("number")){
                JTextField box = new JFormattedTextField(onlyInt);
                box.setText(String.valueOf(getInt(key)));
                panel.add(box);
                configured.put(key, box);
            }
            else {
                String value = getString(key);
                JTextField box = new JTextField(value, value.length());
                box.setColumns(1);
                panel.add(box);
                configured.put(key, box);
            }
        }

        panel.add(new JLabel(""));
        panel.add(new JLabel(""));
        panel.add(buttonResetSettings);
        buttonResetSettings.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Utilities.out("Discarding settings...");
                for(String key: settingsToShow) {
                    Utilities.callbacks.saveExtensionSetting(key, null); // purge saved settings
                }
                setDefaultSettings();
                //BulkScanLauncher.registerDefaults();
                JComponent comp = (JComponent) e.getSource();
                Window win = SwingUtilities.getWindowAncestor(comp);
                win.dispose();

            }
        } );

        int result = JOptionPane.showConfirmDialog(Utilities.getBurpFrame(), scrollPane, "Attack Config", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            for(String key: configured.keySet()) {
                Object val = configured.get(key);
                if (val instanceof JCheckBox) {
                    val = ((JCheckBox) val).isSelected();
                }
                else if (val instanceof JFormattedTextField) {
                    val = Integer.parseInt(((JFormattedTextField) val).getText().replaceAll("[^-\\d]", ""));
                }
                else {
                    val = ((JTextField) val).getText();
                }
                put(key, val);
                Utilities.callbacks.saveExtensionSetting(key, encode(val));
            }

            return new ConfigurableSettings(this);
        }

        return null;
    }



}
