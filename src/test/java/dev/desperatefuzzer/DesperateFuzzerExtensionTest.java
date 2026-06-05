package dev.desperatefuzzer;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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

    @Test
    void lengthOutlierIsSignaledWithinSameEntryAndStatus() throws Exception {
        Object model = newResultTableModel();
        List<Object> rows = new ArrayList<>();

        for (int index = 0; index < 9; index++) {
            rows.add(fuzzResult(1, "base" + index, 200, 1000 + (index % 3)));
        }
        rows.add(fuzzResult(1, "high", 200, 1600));

        addResults(model, rows);

        assertEquals("", signalAt(model, 0));
        assertEquals("outsider", signalAt(model, 9));
    }

    @Test
    void rareLengthBucketIsSignaledOnLargeBaseline() throws Exception {
        Object model = newResultTableModel();
        List<Object> rows = new ArrayList<>();

        for (int index = 0; index < 63; index++) {
            rows.add(fuzzResult(1, "base" + index, 200, 100_000));
        }
        rows.add(fuzzResult(1, "rare-length", 200, 100_300));

        addResults(model, rows);

        assertEquals("", signalAt(model, 0));
        assertEquals("outsider", signalAt(model, 63));
    }

    @Test
    void rareLengthBucketIsSignaledOnTinyBaseline() throws Exception {
        Object model = newResultTableModel();
        List<Object> rows = new ArrayList<>();

        for (int index = 0; index < 15; index++) {
            rows.add(fuzzResult(1, "base" + index, 200, 20));
        }
        rows.add(fuzzResult(1, "rare-length", 200, 22));

        addResults(model, rows);

        assertEquals("", signalAt(model, 0));
        assertEquals("outsider", signalAt(model, 15));
    }

    @Test
    void lengthRarityNeedsAStableDominantBucket() throws Exception {
        Object model = newResultTableModel();
        List<Object> rows = new ArrayList<>();

        rows.add(fuzzResult(1, "one", 200, 100));
        rows.add(fuzzResult(1, "two", 200, 100));
        rows.add(fuzzResult(1, "three", 200, 101));
        rows.add(fuzzResult(1, "four", 200, 102));
        rows.add(fuzzResult(1, "five", 200, 103));
        rows.add(fuzzResult(1, "six", 200, 104));
        rows.add(fuzzResult(1, "seven", 200, 105));
        rows.add(fuzzResult(1, "eight", 200, 106));

        addResults(model, rows);

        for (int row = 0; row < rows.size(); row++) {
            assertEquals("", signalAt(model, row));
        }
    }

    @Test
    void lengthRarityRequiresDominantMajority() throws Exception {
        Object model = newResultTableModel();
        List<Object> rows = new ArrayList<>();

        for (int index = 0; index < 4; index++) {
            rows.add(fuzzResult(1, "base" + index, 200, 100_000));
        }
        rows.add(fuzzResult(1, "jitter1", 200, 100_300));
        rows.add(fuzzResult(1, "jitter2", 200, 100_600));
        rows.add(fuzzResult(1, "jitter3", 200, 100_900));
        rows.add(fuzzResult(1, "jitter4", 200, 101_200));
        rows.add(fuzzResult(1, "jitter5", 200, 101_500));
        rows.add(fuzzResult(1, "jitter6", 200, 101_800));

        addResults(model, rows);

        for (int row = 0; row < rows.size(); row++) {
            assertEquals("", signalAt(model, row));
        }
    }

    @Test
    void rareStatusIsSignaledWithinEntryPoint() throws Exception {
        Object model = newResultTableModel();
        List<Object> rows = new ArrayList<>();

        for (int index = 0; index < 20; index++) {
            rows.add(fuzzResult(1, "ok" + index, 200, 1000));
        }
        rows.add(fuzzResult(1, "rare", 500, 0));

        addResults(model, rows);

        assertEquals("", signalAt(model, 0));
        assertEquals("outsider", signalAt(model, 20));
    }

    @Test
    void tiedStatusGroupsUseOneDeterministicBaseline() throws Exception {
        Object model = newResultTableModel();
        List<Object> rows = new ArrayList<>();

        for (int index = 0; index < 8; index++) {
            rows.add(fuzzResult(1, "ok" + index, 200, 1000));
        }
        for (int index = 0; index < 8; index++) {
            rows.add(fuzzResult(1, "err" + index, 500, 1000));
        }

        addResults(model, rows);

        assertEquals("", signalAt(model, 0));
        assertEquals("interesting", signalAt(model, 8));
    }

    @Test
    void statusTiePrefersHttpStatusOverNoResponseSentinel() throws Exception {
        Object model = newResultTableModel();
        List<Object> rows = new ArrayList<>();

        for (int index = 0; index < 8; index++) {
            rows.add(fuzzResult(1, "no-response" + index, 0, 0));
        }
        for (int index = 0; index < 8; index++) {
            rows.add(fuzzResult(1, "ok" + index, 200, 1000));
        }

        addResults(model, rows);

        assertEquals("interesting", signalAt(model, 0));
        assertEquals("", signalAt(model, 8));
    }

    @Test
    void commonNonBaselineStatusIsStillVisible() throws Exception {
        Object model = newResultTableModel();
        List<Object> rows = new ArrayList<>();

        for (int index = 0; index < 12; index++) {
            rows.add(fuzzResult(1, "ok" + index, 200, 1000));
        }
        for (int index = 0; index < 8; index++) {
            rows.add(fuzzResult(1, "redirect" + index, 302, 1000));
        }

        addResults(model, rows);

        assertEquals("", signalAt(model, 0));
        assertEquals("interesting", signalAt(model, 12));
    }

    @Test
    void lengthOutlierIsSignaledInsideNonDominantStatusGroup() throws Exception {
        Object model = newResultTableModel();
        List<Object> rows = new ArrayList<>();

        for (int index = 0; index < 30; index++) {
            rows.add(fuzzResult(1, "ok" + index, 200, 1000));
        }
        for (int index = 0; index < 6; index++) {
            rows.add(fuzzResult(1, "redirect" + index, 302, 0));
        }
        rows.add(fuzzResult(1, "redirect-body", 302, 500));

        addResults(model, rows);

        assertEquals("interesting", signalAt(model, 30));
        assertEquals("outsider", signalAt(model, 36));
    }

    @Test
    void errorSignatureMatchFindsSpecificLeaks() {
        assertEquals("Oracle ORA", DesperateFuzzerTab.errorSignatureMatch("SQL failed: ORA-00933 near token"));
        assertEquals("Java stack trace", DesperateFuzzerTab.errorSignatureMatch("\tat com.example.App.main(App.java:42)"));
        assertEquals("", DesperateFuzzerTab.errorSignatureMatch("normal application response"));
    }

    @Test
    void errorMatchPromotesResultToInterestingWithoutBaseline() throws Exception {
        Object model = newResultTableModel();

        addResults(model, List.of(fuzzResult(1, "quote", 200, 1000, "Oracle ORA")));

        assertEquals("interesting", signalAt(model, 0));
        assertEquals("Oracle ORA", valueAt(model, 0, 5));
    }

    @Test
    void notesAreShownInMatchColumnWhenNoSignatureMatched() throws Exception {
        Object model = newResultTableModel();

        addResults(model, List.of(fuzzResult(1, "timeout", 0, 0, "", "timeout waiting for response")));

        assertEquals("timeout waiting for response", valueAt(model, 0, 5));
    }

    @Test
    void matchTakesPrecedenceOverNotesInMatchColumn() throws Exception {
        Object model = newResultTableModel();

        addResults(model, List.of(fuzzResult(1, "stack", 500, 1000, "Java stack trace", "timeout")));

        assertEquals("Java stack trace", valueAt(model, 0, 5));
    }

    @Test
    void errorMatchDoesNotDowngradeOutsiderSignal() throws Exception {
        Object model = newResultTableModel();
        List<Object> rows = new ArrayList<>();

        for (int index = 0; index < 9; index++) {
            rows.add(fuzzResult(1, "base" + index, 200, 1000));
        }
        rows.add(fuzzResult(1, "stack", 200, 1600, "Java stack trace"));

        addResults(model, rows);

        assertEquals("outsider", signalAt(model, 9));
        assertEquals("Java stack trace", valueAt(model, 9, 5));
    }

    private static Object newResultTableModel() throws Exception {
        Class<?> modelClass = Class.forName("dev.desperatefuzzer.DesperateFuzzerTab$ResultTableModel");
        Constructor<?> constructor = modelClass.getDeclaredConstructor();
        constructor.setAccessible(true);
        return constructor.newInstance();
    }

    private static Object fuzzResult(int entryPoint, String payload, int statusCode, int responseLength)
            throws Exception {
        return fuzzResult(entryPoint, payload, statusCode, responseLength, "");
    }

    private static Object fuzzResult(int entryPoint, String payload, int statusCode, int responseLength, String match)
            throws Exception {
        return fuzzResult(entryPoint, payload, statusCode, responseLength, match, "");
    }

    private static Object fuzzResult(int entryPoint, String payload, int statusCode, int responseLength, String match,
                                     String notes)
            throws Exception {
        Class<?> resultClass = Class.forName("dev.desperatefuzzer.DesperateFuzzerTab$FuzzResult");
        Constructor<?> constructor = resultClass.getDeclaredConstructor(
                int.class,
                String.class,
                int.class,
                int.class,
                String.class,
                String.class,
                Class.forName("burp.api.montoya.http.message.HttpRequestResponse")
        );
        constructor.setAccessible(true);
        return constructor.newInstance(entryPoint, payload, statusCode, responseLength, match, notes, null);
    }

    private static void addResults(Object model, List<Object> rows) throws Exception {
        Method method = model.getClass().getDeclaredMethod("addAll", List.class);
        method.setAccessible(true);
        method.invoke(model, rows);
    }

    private static String signalAt(Object model, int row) throws Exception {
        Method method = model.getClass().getDeclaredMethod("signalAt", int.class);
        method.setAccessible(true);
        return String.valueOf(method.invoke(model, row));
    }

    private static Object valueAt(Object model, int row, int column) throws Exception {
        Method method = model.getClass().getMethod("getValueAt", int.class, int.class);
        return method.invoke(model, row, column);
    }
}
