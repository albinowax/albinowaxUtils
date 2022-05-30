package burp;

import java.util.ArrayList;
import java.util.LinkedHashSet;

class SettingsBox {
    private LinkedHashSet<String> settings;

    public SettingsBox() {
        settings = new LinkedHashSet<>();
    }

    public void register(String name, Object value) {
        register(name, value, null);
    }

    public void register(String name, Object value, String description) {
        settings.add(name);
        Utilities.globalSettings.registerSetting(name, value, description);
    }

    public boolean contains(String key) {
        return settings.contains(key);
    }

    public void importSettings(SettingsBox newSettings) {
        settings.addAll(newSettings.getSettings());
    }

    public ArrayList<String> getSettings() {
        return new ArrayList<>(settings);
    }
}
