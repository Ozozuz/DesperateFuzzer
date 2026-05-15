package dev.unusualfuzzer;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public final class UnusualFuzzerExtension implements BurpExtension {
    private static final String EXTENSION_NAME = "DesperateFuzzer";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        UnusualFuzzerTab tab = new UnusualFuzzerTab(api);
        api.userInterface().applyThemeToComponent(tab);
        api.userInterface().registerSuiteTab(EXTENSION_NAME, tab);
        api.userInterface().registerContextMenuItemsProvider(tab);

        api.logging().logToOutput(EXTENSION_NAME + " loaded");
    }
}
