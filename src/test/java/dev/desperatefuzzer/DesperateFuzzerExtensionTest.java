package dev.desperatefuzzer;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DesperateFuzzerExtensionTest {
    @Test
    void extensionCanBeInstantiated() {
        assertNotNull(new DesperateFuzzerExtension());
    }

    @Test
    void headerCrAndLfPayloadsStayByteDistinct() {
        String rawRequest = "GET /?q=FUZZ HTTP/1.1\nHost: example.com\n\n";
        int start = rawRequest.indexOf("FUZZ");
        DesperateFuzzerTab.EntryPoint entryPoint = new DesperateFuzzerTab.EntryPoint(start, start + 4, "FUZZ");

        byte[] crRequest = DesperateFuzzerTab.updateContentLength(
                DesperateFuzzerTab.mutateRequest(rawRequest, entryPoint, new byte[]{'\r'}));
        byte[] lfRequest = DesperateFuzzerTab.updateContentLength(
                DesperateFuzzerTab.mutateRequest(rawRequest, entryPoint, new byte[]{'\n'}));
        int payloadOffset = "GET /?q=".length();

        assertFalse(Arrays.equals(crRequest, lfRequest));
        assertEquals('\r', crRequest[payloadOffset]);
        assertEquals(' ', crRequest[payloadOffset + 1]);
        assertEquals('\n', lfRequest[payloadOffset]);
        assertEquals(' ', lfRequest[payloadOffset + 1]);
        assertTrue(new String(crRequest, StandardCharsets.ISO_8859_1).contains("HTTP/1.1\r\nHost:"));
        assertTrue(new String(lfRequest, StandardCharsets.ISO_8859_1).contains("HTTP/1.1\r\nHost:"));
    }

    @Test
    void contentLengthIsUpdatedWithoutChangingBodyPayloadBytes() {
        String rawRequest = "POST / HTTP/1.1\nHost: example.com\nContent-Length: 4\n\nFUZZ";
        int start = rawRequest.indexOf("FUZZ");
        DesperateFuzzerTab.EntryPoint entryPoint = new DesperateFuzzerTab.EntryPoint(start, start + 4, "FUZZ");
        byte[] payload = new byte[]{'A', '\r', 'B', '\n', 'C', 0};

        byte[] updatedRequest = DesperateFuzzerTab.updateContentLength(
                DesperateFuzzerTab.mutateRequest(rawRequest, entryPoint, payload));
        String updatedRequestText = new String(updatedRequest, StandardCharsets.ISO_8859_1);
        int bodyOffset = updatedRequestText.indexOf("\r\n\r\n") + 4;

        assertTrue(updatedRequestText.contains("Content-Length: 6"));
        assertEquals(payload.length, updatedRequest.length - bodyOffset);

        for (int index = 0; index < payload.length; index++) {
            assertEquals(payload[index], updatedRequest[bodyOffset + index]);
        }
    }

    @Test
    void bodyStaticLineEndingsAreNotCanonicalizedAroundPayload() {
        String rawRequest = "POST / HTTP/1.1\nHost: example.com\nContent-Length: 8\n\nA\nFUZZ\rB";
        int start = rawRequest.indexOf("FUZZ");
        DesperateFuzzerTab.EntryPoint entryPoint = new DesperateFuzzerTab.EntryPoint(start, start + 4, "FUZZ");

        byte[] updatedRequest = DesperateFuzzerTab.updateContentLength(
                DesperateFuzzerTab.mutateRequest(rawRequest, entryPoint, new byte[]{'Z'}));
        String updatedRequestText = new String(updatedRequest, StandardCharsets.ISO_8859_1);
        int bodyOffset = updatedRequestText.indexOf("\r\n\r\n") + 4;
        byte[] expectedBody = new byte[]{'A', '\n', 'Z', '\r', 'B'};

        assertTrue(updatedRequestText.contains("Content-Length: 5"));
        assertEquals(expectedBody.length, updatedRequest.length - bodyOffset);

        for (int index = 0; index < expectedBody.length; index++) {
            assertEquals(expectedBody[index], updatedRequest[bodyOffset + index]);
        }
    }
}
