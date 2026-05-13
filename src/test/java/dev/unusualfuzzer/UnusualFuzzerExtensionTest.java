package dev.unusualfuzzer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class UnusualFuzzerExtensionTest {
    @Test
    void extensionCanBeInstantiated() {
        assertNotNull(new UnusualFuzzerExtension());
    }
}
