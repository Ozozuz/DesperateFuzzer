package dev.desperatefuzzer;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public final class DesperateFuzzerExtension implements BurpExtension {
    private static final String EXTENSION_NAME = "DesperateFuzzer";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        DesperateFuzzerTab tab = new DesperateFuzzerTab(api);
        api.userInterface().applyThemeToComponent(tab);
        api.userInterface().registerSuiteTab(EXTENSION_NAME, tab);
        api.userInterface().registerContextMenuItemsProvider(tab);
        api.extension().registerUnloadingHandler(tab::stopActiveScanForUnload);

        api.logging().logToOutput(EXTENSION_NAME + " loaded");
    }
}
