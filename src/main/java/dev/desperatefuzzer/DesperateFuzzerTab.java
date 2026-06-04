package dev.desperatefuzzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.DefaultListModel;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JMenuItem;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import static burp.api.montoya.http.message.requests.HttpRequest.httpRequest;
import static burp.api.montoya.http.message.responses.HttpResponse.httpResponse;

final class DesperateFuzzerTab extends JPanel implements ContextMenuItemsProvider {
    private static final long serialVersionUID = 1L;
    private static final String DEFAULT_REQUEST = "GET /?q=FUZZ HTTP/1.1\r\nHost: example.com\r\n\r\n";
    private static final Pattern CONTENT_LENGTH_PATTERN = Pattern.compile("(?im)^Content-Length:[ \\t]*\\d+[ \\t]*$");
    private static final Map<String, Pattern> ERROR_SIGNATURES = errorSignatures();
    private static final int MAX_MUTATION_CASES_PER_ENTRY_POINT = 512;
    private static final int BOUNDARY_MUTATION_QUOTA = 32;
    private static final int BIT_FLIP_MUTATION_QUOTA = 112;
    private static final int ARITHMETIC_MUTATION_QUOTA = 80;
    private static final int INTERESTING_MUTATION_QUOTA = 128;
    private static final int BLOCK_MUTATION_QUOTA = 96;
    private static final int HAVOC_MUTATION_QUOTA = 63;

    private final MontoyaApi api;
    private final JTextArea requestTextArea;
    private final HttpRequestEditor resultRequestViewer;
    private final HttpResponseEditor resultResponseViewer;
    private final EntryPointTableModel entryPointTableModel;
    private final ResultTableModel resultTableModel;
    private final JTextField targetField;
    private final JComboBox<SpeedProfile> speedProfileComboBox;
    private final JComboBox<EncodingMode> encodingModeComboBox;
    private final DefaultListModel<EncodingMode> encodingPipelineModel;
    private final JList<EncodingMode> encodingPipelineList;
    private final List<EncodingMode> encodingPipeline;
    private final JButton runButton;
    private final JButton mutationButton;
    private final JButton stopButton;
    private final JLabel statusLabel;
    private final List<Object> requestHighlightTags;
    private final Set<String> loggedResultSignals;
    private SwingWorker<List<FuzzResult>, FuzzResult> currentWorker;

    DesperateFuzzerTab(MontoyaApi api) {
        super(new BorderLayout(8, 8));
        this.api = api;
        this.requestTextArea = new JTextArea(DEFAULT_REQUEST);
        this.resultRequestViewer = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.resultResponseViewer = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        this.entryPointTableModel = new EntryPointTableModel();
        this.resultTableModel = new ResultTableModel();
        this.targetField = new JTextField("https://example.com", 34);
        this.speedProfileComboBox = new JComboBox<>(SpeedProfile.values());
        this.encodingModeComboBox = new JComboBox<>(EncodingMode.selectableModes());
        this.encodingPipelineModel = new DefaultListModel<>();
        this.encodingPipelineList = new JList<>(encodingPipelineModel);
        this.encodingPipeline = new ArrayList<>();
        this.runButton = new JButton("Run");
        this.mutationButton = new JButton("Run mutations");
        this.stopButton = new JButton("Stop");
        this.statusLabel = new JLabel("Select request text, then add at least one entry point");
        this.requestHighlightTags = new ArrayList<>();
        this.loggedResultSignals = new HashSet<>();

        stopButton.setEnabled(false);
        refreshEncodingPipeline();
        configureRequestTextArea();

        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        add(buildToolbar(), BorderLayout.NORTH);
        add(buildMainPanel(), BorderLayout.CENTER);
        add(buildStatusPanel(), BorderLayout.SOUTH);
    }

    private void configureRequestTextArea() {
        requestTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        requestTextArea.setLineWrap(false);
        requestTextArea.setTabSize(4);
    }

    private JPanel buildToolbar() {
        JPanel panel = new JPanel(new GridLayout(2, 1, 0, 4));
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JPanel encodingRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton addEntryPointButton = new JButton("Add entry point");
        JButton clearEntryPointsButton = new JButton("Clear entry points");
        JButton addEncodingButton = new JButton("Add encoding");
        JButton removeEncodingButton = new JButton("Remove last");
        JButton clearEncodingButton = new JButton("Clear encoding");
        JButton clearResultsButton = new JButton("Clear results");
        JLabel targetLabel = new JLabel("Target");
        JLabel speedLabel = new JLabel("Profile");
        JLabel encodingLabel = new JLabel("Encoding");

        addEntryPointButton.addActionListener(event -> addSelectedEntryPoint());
        clearEntryPointsButton.addActionListener(event -> clearEntryPoints());
        addEncodingButton.addActionListener(event -> addEncodingToPipeline());
        removeEncodingButton.addActionListener(event -> removeLastEncodingFromPipeline());
        clearEncodingButton.addActionListener(event -> clearEncodingPipeline());
        clearResultsButton.addActionListener(event -> clearResults());
        runButton.addActionListener(event -> runFuzzer());
        mutationButton.addActionListener(event -> runMutationFuzzer());
        stopButton.addActionListener(event -> stopFuzzer());

        actionRow.add(targetLabel);
        actionRow.add(targetField);
        actionRow.add(addEntryPointButton);
        actionRow.add(clearEntryPointsButton);
        actionRow.add(speedLabel);
        actionRow.add(speedProfileComboBox);
        actionRow.add(runButton);
        actionRow.add(mutationButton);
        actionRow.add(stopButton);
        actionRow.add(clearResultsButton);

        encodingRow.add(encodingLabel);
        encodingRow.add(encodingModeComboBox);
        encodingRow.add(addEncodingButton);
        encodingRow.add(removeEncodingButton);
        encodingRow.add(clearEncodingButton);
        encodingRow.add(buildEncodingPipelinePanel());

        panel.add(actionRow);
        panel.add(encodingRow);

        return panel;
    }

    private JScrollPane buildEncodingPipelinePanel() {
        encodingPipelineList.setVisibleRowCount(1);
        encodingPipelineList.setLayoutOrientation(JList.HORIZONTAL_WRAP);
        encodingPipelineList.setFixedCellWidth(88);

        JScrollPane scrollPane = new JScrollPane(encodingPipelineList);
        scrollPane.setPreferredSize(new Dimension(520, 56));
        scrollPane.setBorder(BorderFactory.createTitledBorder("Active encoding pipeline"));

        return scrollPane;
    }

    private JSplitPane buildMainPanel() {
        JSplitPane verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        JSplitPane topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        JSplitPane tableSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        JTable entryPointTable = new JTable(entryPointTableModel);
        JTable resultTable = new JTable(resultTableModel);
        resultTable.setAutoCreateRowSorter(true);
        resultTable.setRowSorter(new TableRowSorter<>(resultTableModel));
        resultTable.setDefaultRenderer(Object.class, new ResultCellRenderer(resultTableModel));
        resultTable.setDefaultRenderer(Integer.class, new ResultCellRenderer(resultTableModel));
        resultTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultTable.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                showSelectedResult(resultTable);
            }
        });

        JScrollPane entryPointScroll = new JScrollPane(entryPointTable);
        JScrollPane resultScroll = new JScrollPane(resultTable);
        JTabbedPane resultDetailTabs = new JTabbedPane();

        entryPointScroll.setBorder(BorderFactory.createTitledBorder("Entry points"));
        entryPointScroll.setPreferredSize(new Dimension(320, 96));
        entryPointScroll.setMinimumSize(new Dimension(220, 72));
        resultScroll.setBorder(BorderFactory.createTitledBorder("Results"));
        resultScroll.setPreferredSize(new Dimension(420, 360));
        resultScroll.setMinimumSize(new Dimension(260, 180));
        resultDetailTabs.addTab("Request", resultRequestViewer.uiComponent());
        resultDetailTabs.addTab("Response", resultResponseViewer.uiComponent());

        tableSplit.setTopComponent(entryPointScroll);
        tableSplit.setBottomComponent(resultScroll);
        tableSplit.setResizeWeight(0.18);

        JScrollPane requestScroll = new JScrollPane(requestTextArea);
        requestScroll.setBorder(BorderFactory.createTitledBorder("Request"));

        topSplit.setLeftComponent(requestScroll);
        topSplit.setRightComponent(tableSplit);
        topSplit.setResizeWeight(0.68);

        verticalSplit.setTopComponent(topSplit);
        verticalSplit.setBottomComponent(resultDetailTabs);
        verticalSplit.setResizeWeight(0.58);

        return verticalSplit;
    }

    private JPanel buildStatusPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(statusLabel, BorderLayout.WEST);
        return panel;
    }

    private void addSelectedEntryPoint() {
        int start = requestTextArea.getSelectionStart();
        int end = requestTextArea.getSelectionEnd();

        if (start < 0 || end < 0) {
            setStatus("No selection: select the insertion point in the request editor");
            return;
        }

        if (start == end) {
            setStatus("Empty selection: select at least one byte");
            return;
        }

        String selectedText = requestTextArea.getSelectedText();
        Optional<EntryPoint> overlappingEntryPoint = entryPointTableModel.overlappingEntryPoint(start, end);
        if (overlappingEntryPoint.isPresent()) {
            EntryPoint existingEntryPoint = overlappingEntryPoint.get();
            setStatus("Overlapping entry point ignored: " + start + "-" + end
                    + " overlaps " + existingEntryPoint.startInclusive() + "-" + existingEntryPoint.endExclusive());
            logToExtension("Overlapping entry point ignored range=" + start + "-" + end
                    + " overlaps=" + existingEntryPoint.startInclusive() + "-" + existingEntryPoint.endExclusive()
                    + " value=\"" + compactForLog(selectedText) + "\"");
            return;
        }

        entryPointTableModel.add(new EntryPoint(start, end, selectedText));
        refreshRequestMarkers();
        setStatus("Entry point added: " + start + "-" + end);
        logToExtension("Entry point #" + entryPointTableModel.getRowCount()
                + " added range=" + start + "-" + end
                + " value=\"" + compactForLog(selectedText) + "\"");
    }

    private void clearEntryPoints() {
        entryPointTableModel.clear();
        refreshRequestMarkers();
    }

    private void addEncodingToPipeline() {
        EncodingMode encodingMode = (EncodingMode) encodingModeComboBox.getSelectedItem();
        if (encodingMode == null) {
            return;
        }

        encodingPipeline.add(encodingMode);
        refreshEncodingPipeline();
    }

    private void clearEncodingPipeline() {
        encodingPipeline.clear();
        refreshEncodingPipeline();
    }

    private void removeLastEncodingFromPipeline() {
        if (encodingPipeline.isEmpty()) {
            return;
        }

        encodingPipeline.remove(encodingPipeline.size() - 1);
        refreshEncodingPipeline();
    }

    private void refreshEncodingPipeline() {
        encodingPipelineModel.clear();

        for (int index = 0; index < encodingPipeline.size(); index++) {
            EncodingMode encodingMode = encodingPipeline.get(index);
            encodingPipelineModel.addElement(encodingMode);
        }
    }

    private String encodingPipelineLabel() {
        return encodingPipeline.stream()
                .map(EncodingMode::toString)
                .reduce((left, right) -> left + " -> " + right)
                .orElse("plain");
    }

    private void runFuzzer() {
        List<EntryPoint> entryPoints = entryPointTableModel.entryPoints();
        if (entryPoints.isEmpty()) {
            setStatus("Add at least one entry point before running");
            return;
        }

        String rawRequest = requestTextArea.getText();
        HttpService targetService;

        try {
            targetService = serviceFromTargetInput();
        } catch (IllegalArgumentException exception) {
            setStatus(exception.getMessage());
            return;
        }

        Optional<EntryPoint> invalidEntryPoint = invalidEntryPoint(rawRequest, entryPoints);

        if (invalidEntryPoint.isPresent()) {
            setStatus("Entry point changed or outside current request. Clear and add it again.");
            return;
        }

        SpeedProfile speedProfile = (SpeedProfile) speedProfileComboBox.getSelectedItem();
        List<EncodingMode> activePipeline = List.copyOf(encodingPipeline);
        List<AsciiPayload> asciiPayloads = EncodingMode.payloadsToSend();
        int totalRequests = entryPoints.size() * asciiPayloads.size();
        Supplier<List<FuzzJob>> jobSupplier = () -> {
            List<FuzzJob> jobs = new ArrayList<>();
            List<EntryPoint> sortedEntryPoints = entryPoints.stream()
                    .sorted(Comparator.comparingInt(EntryPoint::startInclusive))
                    .toList();

            for (int entryPointIndex = 0; entryPointIndex < sortedEntryPoints.size(); entryPointIndex++) {
                EntryPoint entryPoint = sortedEntryPoints.get(entryPointIndex);

                for (AsciiPayload asciiPayload : asciiPayloads) {
                    byte[] payload = applyEncodingPipeline(asciiPayload.payload(), activePipeline);
                    String payloadDisplay = asciiPayload.label();
                    byte[] mutated = mutateRequest(rawRequest, entryPoint, payload);
                    jobs.add(new FuzzJob(entryPointIndex + 1, payloadDisplay, mutated));
                }
            }

            return jobs;
        };

        runScan("ASCII fuzz", "requests", targetService, totalRequests, speedProfile, activePipeline,
                entryPoints, jobSupplier);
    }

    private void runMutationFuzzer() {
        List<EntryPoint> entryPoints = entryPointTableModel.entryPoints();
        if (entryPoints.isEmpty()) {
            setStatus("Add at least one entry point before running mutations");
            return;
        }

        String rawRequest = requestTextArea.getText();
        HttpService targetService;

        try {
            targetService = serviceFromTargetInput();
        } catch (IllegalArgumentException exception) {
            setStatus(exception.getMessage());
            return;
        }

        Optional<EntryPoint> invalidEntryPoint = invalidEntryPoint(rawRequest, entryPoints);

        if (invalidEntryPoint.isPresent()) {
            setStatus("Entry point changed or outside current request. Clear and add it again.");
            return;
        }

        List<EntryPointMutations> mutationPlan = entryPoints.stream()
                .sorted(Comparator.comparingInt(EntryPoint::startInclusive))
                .map(entryPoint -> new EntryPointMutations(entryPoint, generateMutationCases(seedBytes(rawRequest, entryPoint))))
                .toList();
        int totalRequests = mutationPlan.stream().mapToInt(entryPointMutations -> entryPointMutations.mutations().size()).sum();

        if (totalRequests == 0) {
            setStatus("No mutation cases generated");
            return;
        }

        SpeedProfile speedProfile = (SpeedProfile) speedProfileComboBox.getSelectedItem();
        List<EncodingMode> activePipeline = List.copyOf(encodingPipeline);
        Supplier<List<FuzzJob>> jobSupplier = () -> {
            List<FuzzJob> jobs = new ArrayList<>();

            for (int entryPointIndex = 0; entryPointIndex < mutationPlan.size(); entryPointIndex++) {
                EntryPointMutations entryPointMutations = mutationPlan.get(entryPointIndex);

                for (MutationCase mutationCase : entryPointMutations.mutations()) {
                    byte[] encodedPayload = applyEncodingPipeline(mutationCase.payload(), activePipeline);
                    String payloadDisplay = mutationCase.label() + " => " + EncodingMode.printablePayload(encodedPayload);
                    byte[] mutated = mutateRequest(rawRequest, entryPointMutations.entryPoint(), encodedPayload);
                    jobs.add(new FuzzJob(entryPointIndex + 1, payloadDisplay, mutated));
                }
            }

            return jobs;
        };

        runScan("Mutation fuzz", "mutation requests", targetService, totalRequests, speedProfile,
                activePipeline, entryPoints, jobSupplier);
    }

    private void runScan(String scanType, String requestLabel, HttpService targetService, int totalRequests,
                         SpeedProfile speedProfile, List<EncodingMode> activePipeline,
                         List<EntryPoint> entryPoints, Supplier<List<FuzzJob>> jobSupplier) {
        clearResults();
        runButton.setEnabled(false);
        mutationButton.setEnabled(false);
        stopButton.setEnabled(true);
        setStatus("Running " + totalRequests + " " + requestLabel);
        logScanStart(scanType, targetService, entryPoints, speedProfile, activePipeline, totalRequests);

        currentWorker = new SwingWorker<>() {
            @Override
            protected List<FuzzResult> doInBackground() {
                List<FuzzResult> results = new ArrayList<>();
                List<FuzzJob> jobs = jobSupplier.get();
                ExecutorService executor = Executors.newFixedThreadPool(speedProfile.threadCount());
                ExecutorCompletionService<FuzzResult> completionService = new ExecutorCompletionService<>(executor);
                int submittedJobs = 0;

                try {
                    for (FuzzJob job : jobs) {
                        if (isCancelled()) {
                            break;
                        }

                        completionService.submit(() -> sendMutatedRequest(targetService, job.request(), job.entryPoint(), job.payload()));
                        submittedJobs++;
                    }

                    for (int completedJobs = 0; completedJobs < submittedJobs; completedJobs++) {
                        if (isCancelled()) {
                            break;
                        }

                        Future<FuzzResult> future = completionService.take();
                        FuzzResult result = future.get();
                        results.add(result);
                        publish(result);
                    }
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                } catch (ExecutionException exception) {
                    api.logging().logToError(exception.toString());
                } finally {
                    executor.shutdownNow();
                }

                return results;
            }

            @Override
            protected void process(List<FuzzResult> chunks) {
                AddedRows addedRows = resultTableModel.addAll(chunks);
                logNewResultSignals(addedRows);
                setStatus("Sent " + resultTableModel.getRowCount() + " / " + totalRequests);
            }

            @Override
            protected void done() {
                runButton.setEnabled(true);
                mutationButton.setEnabled(true);
                stopButton.setEnabled(false);

                try {
                    int count = get().size();
                    if (isCancelled()) {
                        setStatus("Stopped: " + resultTableModel.getRowCount() + " requests sent");
                        logToExtension(scanType + " stopped results=" + resultTableModel.getRowCount());
                    } else {
                        setStatus("Completed: " + count + " " + requestLabel + " sent");
                        logToExtension(scanType + " completed results=" + count);
                    }
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    setStatus("Interrupted");
                    logToExtension(scanType + " interrupted results=" + resultTableModel.getRowCount());
                } catch (java.util.concurrent.CancellationException exception) {
                    setStatus("Stopped: " + resultTableModel.getRowCount() + " requests sent");
                    logToExtension(scanType + " stopped results=" + resultTableModel.getRowCount());
                } catch (ExecutionException exception) {
                    api.logging().logToError(exception.toString());
                    setStatus("Failed: " + exception.getCause().getMessage());
                    logToExtension(scanType + " failed: " + exception.getCause().getMessage());
                } finally {
                    currentWorker = null;
                }
            }
        };

        currentWorker.execute();
    }

    private void stopFuzzer() {
        cancelActiveScan("Stopping...", "Scan stop requested after " + resultTableModel.getRowCount() + " results");
    }

    void stopActiveScanForUnload() {
        cancelActiveScan("Extension unloading: stopping scan...",
                "Extension unload cancelled active scan after " + resultTableModel.getRowCount() + " results");
    }

    private void cancelActiveScan(String statusMessage, String logMessage) {
        if (currentWorker != null && !currentWorker.isDone()) {
            currentWorker.cancel(true);
            setStatus(statusMessage);
            logToExtension(logMessage);
        }
    }

    private FuzzResult sendMutatedRequest(HttpService targetService, byte[] mutatedRequest, int entryPoint, String payload) {
        try {
            HttpRequest request = httpRequest(targetService, ByteArray.byteArray(updateContentLength(mutatedRequest)));
            HttpRequestResponse requestResponse = api.http().sendRequest(request);

            if (!requestResponse.hasResponse()) {
                return new FuzzResult(entryPoint, payload, 0, 0, "", "No response", requestResponse);
            }

            String errorMatch = errorSignatureMatch(requestResponse.response().bodyToString());

            return new FuzzResult(
                    entryPoint,
                    payload,
                    requestResponse.response().statusCode(),
                    requestResponse.response().body().length(),
                    errorMatch,
                    "",
                    requestResponse
            );
        } catch (RuntimeException exception) {
            return new FuzzResult(entryPoint, payload, 0, 0, "", exceptionMessage(exception), null);
        }
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (!event.isFromTool(ToolType.REPEATER)) {
            return List.of();
        }

        Optional<HttpRequest> request = requestFromContextMenu(event);
        if (request.isEmpty()) {
            return List.of();
        }

        JMenuItem menuItem = new JMenuItem("Send to DesperateFuzzer");
        menuItem.addActionListener(action -> loadRequest(request.get()));

        return List.of(menuItem);
    }

    private Optional<HttpRequest> requestFromContextMenu(ContextMenuEvent event) {
        Optional<HttpRequest> editorRequest = event.messageEditorRequestResponse()
                .map(messageEditorRequestResponse -> messageEditorRequestResponse.requestResponse().request());

        if (editorRequest.isPresent()) {
            return editorRequest;
        }

        return event.selectedRequestResponses().stream()
                .findFirst()
                .map(HttpRequestResponse::request);
    }

    private void loadRequest(HttpRequest request) {
        SwingUtilities.invokeLater(() -> {
            clearRequestEditorHighlights();
            requestTextArea.setText(request.toString());
            requestTextArea.setCaretPosition(0);
            targetField.setText(targetFromRequest(request));
            entryPointTableModel.clear();
            clearResults();
            setStatus("Loaded request from Repeater");
        });
    }

    private void refreshRequestMarkers() {
        int requestLength = requestTextArea.getText().length();
        List<EntryPoint> entryPoints = entryPointTableModel.entryPoints();
        SwingUtilities.invokeLater(this::applyRequestEditorHighlights);

        if (entryPoints.isEmpty()) {
            return;
        }

        EntryPoint lastEntryPoint = entryPoints.get(entryPoints.size() - 1);
        if (lastEntryPoint.startInclusive() >= 0 && lastEntryPoint.startInclusive() <= requestLength) {
            requestTextArea.setCaretPosition(lastEntryPoint.startInclusive());
        }
    }

    private void applyRequestEditorHighlights() {
        clearRequestEditorHighlights();
        Highlighter highlighter = requestTextArea.getHighlighter();
        DefaultHighlighter.DefaultHighlightPainter painter =
                new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 238, 128));
        int documentLength = requestTextArea.getDocument().getLength();

        for (EntryPoint entryPoint : entryPointTableModel.entryPoints()) {
            if (entryPoint.startInclusive() < 0 || entryPoint.endExclusive() > documentLength) {
                continue;
            }

            try {
                Object tag = highlighter.addHighlight(entryPoint.startInclusive(), entryPoint.endExclusive(), painter);
                requestHighlightTags.add(tag);
            } catch (BadLocationException exception) {
                api.logging().logToError("Unable to paint entry point highlight: " + exception.getMessage());
            }
        }
    }

    private void clearRequestEditorHighlights() {
        Highlighter highlighter = requestTextArea.getHighlighter();
        for (Object tag : requestHighlightTags) {
            highlighter.removeHighlight(tag);
        }

        requestHighlightTags.clear();
    }

    private String targetFromRequest(HttpRequest request) {
        HttpService service = request.httpService();
        String scheme = service.secure() ? "https" : "http";
        int defaultPort = defaultPort(service.secure());

        if (service.port() == defaultPort) {
            return scheme + "://" + service.host();
        }

        return scheme + "://" + service.host() + ":" + service.port();
    }

    private HttpService serviceFromTargetInput() {
        Target target = parseTarget(targetField.getText().trim());
        return HttpService.httpService(target.host(), target.port(), target.secure());
    }

    private Target parseTarget(String targetText) {
        if (targetText.isBlank()) {
            throw new IllegalArgumentException("Missing target. Use https://host[:port] or http://host[:port]");
        }

        String normalizedTarget = targetText.contains("://") ? targetText : "https://" + targetText;

        try {
            URI uri = new URI(normalizedTarget);
            String scheme = uri.getScheme();
            boolean secure;

            if ("https".equalsIgnoreCase(scheme)) {
                secure = true;
            } else if ("http".equalsIgnoreCase(scheme)) {
                secure = false;
            } else {
                throw new IllegalArgumentException("Target scheme must be http or https");
            }

            String host = uri.getHost();
            if (host == null || host.isBlank()) {
                throw new IllegalArgumentException("Invalid target host");
            }

            int port = uri.getPort() == -1 ? defaultPort(secure) : uri.getPort();
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Invalid target port");
            }

            return new Target(host, port, secure);
        } catch (URISyntaxException exception) {
            throw new IllegalArgumentException("Invalid target. Use https://host[:port] or http://host[:port]");
        }
    }

    private int defaultPort(boolean secure) {
        return secure ? 443 : 80;
    }

    private Optional<EntryPoint> invalidEntryPoint(String rawRequest, List<EntryPoint> entryPoints) {
        return entryPoints.stream()
                .filter(entryPoint -> entryPoint.endExclusive() > rawRequest.length()
                        || !rawRequest.substring(entryPoint.startInclusive(), entryPoint.endExclusive())
                        .equals(entryPoint.selectedText()))
                .findFirst();
    }

    private byte[] seedBytes(String rawRequest, EntryPoint entryPoint) {
        return rawRequest.substring(entryPoint.startInclusive(), entryPoint.endExclusive()).getBytes(StandardCharsets.ISO_8859_1);
    }

    private List<MutationCase> generateMutationCases(byte[] seed) {
        LinkedHashMap<String, MutationCase> selected = new LinkedHashMap<>();
        List<MutationGroup> groups = List.of(
                mutationGroup(BOUNDARY_MUTATION_QUOTA, this::addBoundaryMutations),
                mutationGroup(BIT_FLIP_MUTATION_QUOTA, mutations -> addBitFlipMutations(mutations, seed)),
                mutationGroup(ARITHMETIC_MUTATION_QUOTA, mutations -> addArithmeticMutations(mutations, seed)),
                mutationGroup(INTERESTING_MUTATION_QUOTA, mutations -> addInterestingValueMutations(mutations, seed)),
                mutationGroup(BLOCK_MUTATION_QUOTA, mutations -> addBlockMutations(mutations, seed)),
                mutationGroup(HAVOC_MUTATION_QUOTA, mutations -> addHavocMutations(mutations, seed))
        );

        addMutation(selected, "seed/original", seed);

        for (MutationGroup group : groups) {
            addMutationQuota(selected, group);
        }

        addRemainingMutations(selected, groups);

        return List.copyOf(selected.values());
    }

    private MutationGroup mutationGroup(int quota, Consumer<LinkedHashMap<String, MutationCase>> mutationBuilder) {
        LinkedHashMap<String, MutationCase> mutations = new LinkedHashMap<>();
        mutationBuilder.accept(mutations);
        return new MutationGroup(quota, List.copyOf(mutations.values()));
    }

    private void addMutationQuota(LinkedHashMap<String, MutationCase> selected, MutationGroup group) {
        int added = 0;

        for (MutationCase mutationCase : group.mutations()) {
            if (selected.size() >= MAX_MUTATION_CASES_PER_ENTRY_POINT || added >= group.quota()) {
                return;
            }

            if (addMutation(selected, mutationCase.label(), mutationCase.payload())) {
                added++;
            }
        }
    }

    private void addRemainingMutations(LinkedHashMap<String, MutationCase> selected, List<MutationGroup> groups) {
        int[] indexes = new int[groups.size()];
        boolean advanced;

        do {
            advanced = false;

            for (int groupIndex = 0; groupIndex < groups.size(); groupIndex++) {
                if (selected.size() >= MAX_MUTATION_CASES_PER_ENTRY_POINT) {
                    return;
                }

                MutationGroup group = groups.get(groupIndex);
                if (indexes[groupIndex] >= group.mutations().size()) {
                    continue;
                }

                MutationCase mutationCase = group.mutations().get(indexes[groupIndex]);
                indexes[groupIndex]++;
                advanced = true;
                addMutation(selected, mutationCase.label(), mutationCase.payload());
            }
        } while (advanced);
    }

    private void addBoundaryMutations(LinkedHashMap<String, MutationCase> mutations) {
        String[] boundaries = {
                "",
                "0",
                "1",
                "-1",
                "true",
                "false",
                "null",
                "NaN",
                "Infinity",
                "2147483647",
                "-2147483648",
                "4294967295",
                "../",
                "../../",
                "\"",
                "'",
                "\\",
                "\u0000",
                repeat('A', 64),
                repeat('A', 256),
                repeat('A', 1024)
        };

        for (String boundary : boundaries) {
            addMutation(mutations, "boundary:" + printableLabel(boundary.getBytes(StandardCharsets.ISO_8859_1)), boundary.getBytes(StandardCharsets.ISO_8859_1));
        }
    }

    private void addBitFlipMutations(LinkedHashMap<String, MutationCase> mutations, byte[] seed) {
        int length = Math.min(seed.length, 32);

        for (int index = 0; index < length; index++) {
            byte[] byteFlip = seed.clone();
            byteFlip[index] = (byte) (byteFlip[index] ^ 0xFF);
            addMutation(mutations, "byteflip@" + index, byteFlip);

            for (int bit = 0; bit < 8; bit++) {
                byte[] bitFlip = seed.clone();
                bitFlip[index] = (byte) (bitFlip[index] ^ (1 << bit));
                addMutation(mutations, "bitflip@" + index + "." + bit, bitFlip);
            }
        }
    }

    private void addArithmeticMutations(LinkedHashMap<String, MutationCase> mutations, byte[] seed) {
        int length = Math.min(seed.length, 64);
        int[] deltas = {-35, -16, -1, 1, 16, 35};

        for (int index = 0; index < length; index++) {
            int original = seed[index] & 0xFF;

            for (int delta : deltas) {
                byte[] mutated = seed.clone();
                mutated[index] = (byte) ((original + delta) & 0xFF);
                addMutation(mutations, "arith" + signed(delta) + "@" + index, mutated);
            }
        }
    }

    private void addInterestingValueMutations(LinkedHashMap<String, MutationCase> mutations, byte[] seed) {
        int length = Math.min(seed.length, 64);
        int[] interestingValues = {0x00, 0x01, 0x02, 0x07, 0x08, 0x09, 0x0A, 0x0D, 0x1F, 0x20, 0x22, 0x27, 0x2F, 0x5C, 0x7F, 0x80, 0xFE, 0xFF};

        for (int index = 0; index < length; index++) {
            for (int value : interestingValues) {
                byte[] mutated = seed.clone();
                mutated[index] = (byte) value;
                addMutation(mutations, String.format("interesting:0x%02X@%d", value, index), mutated);
            }
        }
    }

    private void addBlockMutations(LinkedHashMap<String, MutationCase> mutations, byte[] seed) {
        if (seed.length == 0) {
            return;
        }

        int maxPosition = Math.min(seed.length, 32);
        byte[][] tokens = {
                ascii("%00"),
                ascii("../"),
                ascii("{{7*7}}"),
                ascii("${7*7}"),
                ascii("<script>alert(1)</script>")
        };

        for (int index = 0; index < maxPosition; index++) {
            addMutation(mutations, "delete-byte@" + index, concat(
                    Arrays.copyOfRange(seed, 0, index),
                    Arrays.copyOfRange(seed, index + 1, seed.length)
            ));

            addMutation(mutations, "duplicate-byte@" + index, concat(
                    Arrays.copyOfRange(seed, 0, index),
                    new byte[]{seed[index]},
                    Arrays.copyOfRange(seed, index, seed.length)
            ));
        }

        int[] positions = {0, seed.length / 2, seed.length};
        for (int position : positions) {
            for (byte[] token : tokens) {
                addMutation(mutations, "insert:" + printableLabel(token) + "@" + position, concat(
                        Arrays.copyOfRange(seed, 0, position),
                        token,
                        Arrays.copyOfRange(seed, position, seed.length)
                ));
                addMutation(mutations, "replace:" + printableLabel(token) + "@" + position, token);
            }
        }
    }

    private void addHavocMutations(LinkedHashMap<String, MutationCase> mutations, byte[] seed) {
        Random random = new Random(Arrays.hashCode(seed) ^ 0x5F3759DF);

        for (int round = 0; round < 128; round++) {
            byte[] mutated = seed.clone();
            int stack = 1 + random.nextInt(4);

            for (int operation = 0; operation < stack; operation++) {
                mutated = applyHavocOperation(mutated, random);
            }

            addMutation(mutations, "havoc#" + round, mutated);
        }
    }

    private byte[] applyHavocOperation(byte[] input, Random random) {
        if (input.length == 0) {
            return new byte[]{(byte) random.nextInt(256)};
        }

        int operation = random.nextInt(7);
        int index = random.nextInt(input.length);
        byte[] mutated = input.clone();

        return switch (operation) {
            case 0 -> {
                mutated[index] = (byte) (mutated[index] ^ (1 << random.nextInt(8)));
                yield mutated;
            }
            case 1 -> {
                mutated[index] = (byte) random.nextInt(256);
                yield mutated;
            }
            case 2 -> {
                mutated[index] = (byte) (((mutated[index] & 0xFF) + random.nextInt(71) - 35) & 0xFF);
                yield mutated;
            }
            case 3 -> concat(Arrays.copyOfRange(input, 0, index), Arrays.copyOfRange(input, index + 1, input.length));
            case 4 -> concat(Arrays.copyOfRange(input, 0, index), new byte[]{input[index]}, Arrays.copyOfRange(input, index, input.length));
            case 5 -> concat(Arrays.copyOfRange(input, 0, index), ascii("%" + String.format("%02X", random.nextInt(256))), Arrays.copyOfRange(input, index, input.length));
            default -> concat(input, ascii(String.valueOf(random.nextInt())));
        };
    }

    private boolean addMutation(LinkedHashMap<String, MutationCase> mutations, String label, byte[] payload) {
        String key = Arrays.toString(payload);
        if (mutations.containsKey(key)) {
            return false;
        }

        mutations.put(key, new MutationCase(label, payload));
        return true;
    }

    private byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private byte[] concat(byte[]... arrays) {
        int size = 0;
        for (byte[] array : arrays) {
            size += array.length;
        }

        byte[] output = new byte[size];
        int offset = 0;

        for (byte[] array : arrays) {
            System.arraycopy(array, 0, output, offset, array.length);
            offset += array.length;
        }

        return output;
    }

    private String repeat(char value, int count) {
        char[] chars = new char[count];
        Arrays.fill(chars, value);
        return new String(chars);
    }

    private String signed(int value) {
        return value > 0 ? "+" + value : String.valueOf(value);
    }

    private String printableLabel(byte[] value) {
        if (value.length == 0) {
            return "<empty>";
        }

        StringBuilder builder = new StringBuilder();

        for (int index = 0; index < Math.min(value.length, 24); index++) {
            int current = value[index] & 0xFF;

            if (current >= 0x20 && current <= 0x7E) {
                builder.append((char) current);
            } else {
                builder.append(String.format("\\x%02X", current));
            }
        }

        if (value.length > 24) {
            builder.append("...");
        }

        return builder.toString();
    }

    private byte[] applyEncodingPipeline(byte[] payload, List<EncodingMode> pipeline) {
        for (EncodingMode encodingMode : pipeline) {
            payload = encodingMode.apply(payload);
        }

        return payload;
    }

    static byte[] mutateRequest(String rawRequest, EntryPoint entryPoint, byte[] payload) {
        int bodyStart = bodyStartOffset(rawRequest);
        byte[] prefix = staticRequestPartBytes(rawRequest, 0, entryPoint.startInclusive(), bodyStart);
        byte[] suffix = staticRequestPartBytes(rawRequest, entryPoint.endExclusive(), rawRequest.length(), bodyStart);
        byte[] mutated = new byte[prefix.length + payload.length + suffix.length];

        System.arraycopy(prefix, 0, mutated, 0, prefix.length);
        System.arraycopy(payload, 0, mutated, prefix.length, payload.length);
        System.arraycopy(suffix, 0, mutated, prefix.length + payload.length, suffix.length);

        return mutated;
    }

    private static byte[] staticRequestPartBytes(String rawRequest, int startInclusive, int endExclusive, int bodyStart) {
        if (bodyStart < 0 || endExclusive <= bodyStart) {
            return canonicalizeLineEndings(rawRequest.substring(startInclusive, endExclusive))
                    .getBytes(StandardCharsets.ISO_8859_1);
        }

        if (startInclusive >= bodyStart) {
            return rawRequest.substring(startInclusive, endExclusive).getBytes(StandardCharsets.ISO_8859_1);
        }

        byte[] headerBytes = canonicalizeLineEndings(rawRequest.substring(startInclusive, bodyStart))
                .getBytes(StandardCharsets.ISO_8859_1);
        byte[] bodyBytes = rawRequest.substring(bodyStart, endExclusive).getBytes(StandardCharsets.ISO_8859_1);
        byte[] output = new byte[headerBytes.length + bodyBytes.length];

        System.arraycopy(headerBytes, 0, output, 0, headerBytes.length);
        System.arraycopy(bodyBytes, 0, output, headerBytes.length, bodyBytes.length);

        return output;
    }

    private static int bodyStartOffset(String rawRequest) {
        int separatorOffset = rawRequest.indexOf("\r\n\r\n");
        if (separatorOffset >= 0) {
            return separatorOffset + 4;
        }

        separatorOffset = rawRequest.indexOf("\n\n");
        if (separatorOffset >= 0) {
            return separatorOffset + 2;
        }

        return -1;
    }

    private static String canonicalizeLineEndings(String requestPart) {
        return requestPart
                .replace("\r\n", "\n")
                .replace('\r', '\n')
                .replace("\n", "\r\n");
    }

    static byte[] updateContentLength(byte[] rawRequest) {
        HeaderBodySplit split = splitHeaderAndBody(rawRequest);

        if (split == null) {
            return rawRequest;
        }

        String headers = new String(split.headers(), StandardCharsets.ISO_8859_1);

        if (!CONTENT_LENGTH_PATTERN.matcher(headers).find()) {
            return rawRequest;
        }

        headers = CONTENT_LENGTH_PATTERN.matcher(headers)
                .replaceFirst("Content-Length: " + split.body().length);

        byte[] headerBytes = headers.getBytes(StandardCharsets.ISO_8859_1);
        byte[] separatorBytes = split.separator();
        byte[] normalized = new byte[headerBytes.length + separatorBytes.length + split.body().length];

        System.arraycopy(headerBytes, 0, normalized, 0, headerBytes.length);
        System.arraycopy(separatorBytes, 0, normalized, headerBytes.length, separatorBytes.length);
        System.arraycopy(split.body(), 0, normalized, headerBytes.length + separatorBytes.length, split.body().length);

        return normalized;
    }

    private static HeaderBodySplit splitHeaderAndBody(byte[] rawRequest) {
        int bodyOffset = indexOf(rawRequest, new byte[]{'\r', '\n', '\r', '\n'});
        int separatorLength = 4;

        if (bodyOffset < 0) {
            bodyOffset = indexOf(rawRequest, new byte[]{'\n', '\n'});
            separatorLength = 2;
        }

        if (bodyOffset < 0) {
            return null;
        }

        return new HeaderBodySplit(
                Arrays.copyOfRange(rawRequest, 0, bodyOffset),
                Arrays.copyOfRange(rawRequest, bodyOffset, bodyOffset + separatorLength),
                Arrays.copyOfRange(rawRequest, bodyOffset + separatorLength, rawRequest.length)
        );
    }

    private static int indexOf(byte[] source, byte[] search) {
        for (int index = 0; index <= source.length - search.length; index++) {
            boolean match = true;

            for (int searchIndex = 0; searchIndex < search.length; searchIndex++) {
                if (source[index + searchIndex] != search[searchIndex]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                return index;
            }
        }

        return -1;
    }

    private void showSelectedResult(JTable resultTable) {
        int selectedRow = resultTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }

        int modelRow = resultTable.convertRowIndexToModel(selectedRow);
        FuzzResult result = resultTableModel.resultAt(modelRow);

        if (result.requestResponse() == null) {
            return;
        }

        resultRequestViewer.setRequest(result.requestResponse().request());

        if (result.requestResponse().hasResponse()) {
            resultResponseViewer.setResponse(result.requestResponse().response());
        } else {
            resultResponseViewer.setResponse(httpResponse(""));
        }
    }

    private void clearResults() {
        resultTableModel.clear();
        loggedResultSignals.clear();
        resultRequestViewer.setRequest(HttpRequest.httpRequest(HttpService.httpService("example.com", 80, false), DEFAULT_REQUEST));
        resultResponseViewer.setResponse(httpResponse(""));
    }

    private void logScanStart(String scanType, HttpService targetService, List<EntryPoint> entryPoints,
                              SpeedProfile speedProfile, List<EncodingMode> activePipeline, int totalRequests) {
        logToExtension(scanType + " started target=" + targetFromService(targetService)
                + " profile=\"" + speedProfile + "\""
                + " encoding=\"" + encodingPipelineLabel(activePipeline) + "\""
                + " entryPoints=" + entryPoints.size()
                + " requests=" + totalRequests);

        for (int index = 0; index < entryPoints.size(); index++) {
            EntryPoint entryPoint = entryPoints.get(index);
            logToExtension("Entry point #" + (index + 1)
                    + " range=" + entryPoint.startInclusive() + "-" + entryPoint.endExclusive()
                    + " seed=\"" + compactForLog(entryPoint.selectedText()) + "\"");
        }
    }

    private void logNewResultSignals(AddedRows addedRows) {
        for (int row : addedRows.changedSignalRows()) {
            logResultSignal(row);
        }

        for (int row = addedRows.firstInsertedRow(); row < addedRows.lastInsertedExclusive(); row++) {
            logResultSignal(row);
        }
    }

    private void logResultSignal(int row) {
        if (row < 0 || row >= resultTableModel.getRowCount()) {
            return;
        }

        ResultSignal signal = resultTableModel.signalAt(row);
        if (signal == ResultSignal.NORMAL) {
            return;
        }

        FuzzResult result = resultTableModel.resultAt(row);
        String key = signal + "|" + result.entryPoint() + "|" + result.payload() + "|" + result.statusCode()
                + "|" + result.responseLength() + "|" + result.match();

        if (loggedResultSignals.add(key)) {
            logToExtension(signal + " found entry=" + result.entryPoint()
                    + " payload=\"" + compactForLog(result.payload()) + "\""
                    + " status=" + result.statusCode()
                    + " length=" + result.responseLength()
                    + (result.match().isBlank() ? "" : " match=\"" + compactForLog(result.match()) + "\""));
        }
    }

    private String targetFromService(HttpService service) {
        String scheme = service.secure() ? "https" : "http";
        int defaultPort = defaultPort(service.secure());

        if (service.port() == defaultPort) {
            return scheme + "://" + service.host();
        }

        return scheme + "://" + service.host() + ":" + service.port();
    }

    private String encodingPipelineLabel(List<EncodingMode> pipeline) {
        return pipeline.stream()
                .map(EncodingMode::toString)
                .reduce((left, right) -> left + " -> " + right)
                .orElse("plain");
    }

    private String compactForLog(String value) {
        String compact = value
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace("\t", "\\t");

        if (compact.length() > 120) {
            return compact.substring(0, 117) + "...";
        }

        return compact;
    }

    private void logToExtension(String message) {
        api.logging().logToOutput("[DesperateFuzzer] " + message);
    }

    private static Map<String, Pattern> errorSignatures() {
        LinkedHashMap<String, Pattern> signatures = new LinkedHashMap<>();

        addErrorSignature(signatures, "SQLSTATE", "\\bSQLSTATE(?:\\[[^\\]]+\\])?\\b");
        addErrorSignature(signatures, "Oracle ORA", "\\bORA-\\d{5}\\b");
        addErrorSignature(signatures, "PostgreSQL exception", "\\bPSQLException\\b");
        addErrorSignature(signatures, "MySQL syntax error", "You have an error in your SQL syntax");
        addErrorSignature(signatures, "SQLite exception", "\\bSQLiteException\\b");
        addErrorSignature(signatures, "ODBC", "\\bODBC\\b");
        addErrorSignature(signatures, "PostgreSQL syntax near", "syntax error at or near");
        addErrorSignature(signatures, "Unterminated quoted string", "unterminated quoted string");
        addErrorSignature(signatures, "Python traceback", "Traceback \\(most recent call last\\)");
        addErrorSignature(signatures, "Java stack trace", "\\bat\\s+[\\w.$]+\\([\\w.$]+:\\d+\\)");
        addErrorSignature(signatures, ".NET exception", "\\bSystem\\.[\\w.]+Exception\\b");
        addErrorSignature(signatures, "Spring framework", "\\borg\\.springframework\\b");
        addErrorSignature(signatures, "Go goroutine", "\\bgoroutine\\s+\\d+\\b");
        addErrorSignature(signatures, "Go panic", "\\bpanic:");
        addErrorSignature(signatures, "PHP warning", "\\bWarning:\\s");
        addErrorSignature(signatures, "PHP fatal error", "\\bFatal error\\b");
        addErrorSignature(signatures, "Uncaught exception", "\\bUncaught\\s");
        addErrorSignature(signatures, "Internal Server Error", "\\bInternal Server Error\\b");
        addErrorSignature(signatures, "Stack trace", "\\bstack trace\\b");
        addErrorSignature(signatures, "Django DEBUG", "\\bDEBUG\\s*=\\s*True\\b");
        addErrorSignature(signatures, "Laravel Whoops", "Whoops, looks like something went wrong");

        return Collections.unmodifiableMap(signatures);
    }

    private static void addErrorSignature(Map<String, Pattern> signatures, String name, String regex) {
        signatures.put(name, Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE));
    }

    static String errorSignatureMatch(String responseBody) {
        if (responseBody == null || responseBody.isEmpty()) {
            return "";
        }

        for (Map.Entry<String, Pattern> signature : ERROR_SIGNATURES.entrySet()) {
            if (signature.getValue().matcher(responseBody).find()) {
                return signature.getKey();
            }
        }

        return "";
    }

    private static String exceptionMessage(RuntimeException exception) {
        String message = exception.getMessage();
        if (message == null || message.isBlank()) {
            return exception.getClass().getSimpleName();
        }

        return message;
    }

    private void setStatus(String message) {
        if (SwingUtilities.isEventDispatchThread()) {
            statusLabel.setText(message);
            return;
        }

        SwingUtilities.invokeLater(() -> statusLabel.setText(message));
    }

    record EntryPoint(int startInclusive, int endExclusive, String selectedText) {
    }

    private record MutationCase(String label, byte[] payload) {
    }

    private record MutationGroup(int quota, List<MutationCase> mutations) {
    }

    private record EntryPointMutations(EntryPoint entryPoint, List<MutationCase> mutations) {
    }

    private record FuzzJob(int entryPoint, String payload, byte[] request) {
    }

    private record AddedRows(int firstInsertedRow, int lastInsertedExclusive, List<Integer> changedSignalRows) {
    }

    private record AsciiPayload(String label, byte[] payload) {
    }

    private enum SpeedProfile {
        GIUSEPPE("giuseppe [2 threads]", 2),
        JACOPO("jacopo [6 threads]", 6),
        GIULIO("giulio [10 threads]", 10);

        private final String label;
        private final int threadCount;

        SpeedProfile(String label, int threadCount) {
            this.label = label;
            this.threadCount = threadCount;
        }

        int threadCount() {
            return threadCount;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private enum EncodingMode {
        PLAIN("plain") {
            @Override
            byte[] apply(byte[] input) {
                return input;
            }
        },
        URL("url") {
            @Override
            byte[] apply(byte[] input) {
                StringBuilder builder = new StringBuilder(input.length * 3);

                for (byte value : input) {
                    builder.append(String.format("%%%02X", value & 0xFF));
                }

                return ascii(builder.toString());
            }
        },
        HTML("html") {
            @Override
            byte[] apply(byte[] input) {
                StringBuilder builder = new StringBuilder(input.length * 6);

                for (byte value : input) {
                    builder.append(String.format("&#x%02X;", value & 0xFF));
                }

                return ascii(builder.toString());
            }
        },
        UNICODE("unicode") {
            @Override
            byte[] apply(byte[] input) {
                StringBuilder builder = new StringBuilder(input.length * 6);

                for (byte value : input) {
                    builder.append(String.format("\\u%04X", value & 0xFF));
                }

                return ascii(builder.toString());
            }
        },
        BASE64("base64") {
            @Override
            byte[] apply(byte[] input) {
                return ascii(Base64.getEncoder().encodeToString(input));
            }
        };

        private final String label;

        EncodingMode(String label) {
            this.label = label;
        }

        abstract byte[] apply(byte[] input);

        static List<AsciiPayload> payloadsToSend() {
            List<AsciiPayload> payloads = new ArrayList<>(0x101);

            for (int value = 0; value < 0x100; value++) {
                payloads.add(new AsciiPayload(display(value), new byte[]{(byte) value}));
            }

            payloads.add(new AsciiPayload("0x0D0x0A", new byte[]{'\r', '\n'}));
            return payloads;
        }

        static EncodingMode[] selectableModes() {
            return new EncodingMode[]{URL, HTML, UNICODE, BASE64};
        }

        static String display(int value) {
            if (value >= 0x20 && value <= 0x7E) {
                return String.valueOf((char) value);
            }

            return String.format("%%%02X", value);
        }

        static String printablePayload(byte[] payload) {
            StringBuilder builder = new StringBuilder();

            for (int index = 0; index < Math.min(payload.length, 80); index++) {
                int current = payload[index] & 0xFF;

                if (current >= 0x20 && current <= 0x7E) {
                    builder.append((char) current);
                } else {
                    builder.append(String.format("\\x%02X", current));
                }
            }

            if (payload.length > 80) {
                builder.append("...");
            }

            return builder.toString();
        }

        byte[] ascii(String value) {
            return value.getBytes(StandardCharsets.US_ASCII);
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private record Target(String host, int port, boolean secure) {
    }

    private record HeaderBodySplit(byte[] headers, byte[] separator, byte[] body) {
    }

    private record FuzzResult(int entryPoint, String payload, int statusCode, int responseLength, String match,
                              String notes, HttpRequestResponse requestResponse) {
        private FuzzResult {
            if (match == null) {
                match = "";
            }

            if (notes == null) {
                notes = "";
            }
        }
    }

    private enum ResultSignal {
        NORMAL(""),
        INTERESTING("interesting"),
        OUTSIDER("outsider");

        private final String label;

        ResultSignal(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private static final class ResultCellRenderer extends DefaultTableCellRenderer {
        private static final long serialVersionUID = 1L;
        private static final Color INTERESTING_BACKGROUND = new Color(255, 246, 204);
        private static final Color OUTSIDER_BACKGROUND = new Color(136, 72, 72);
        private static final Color SELECTED_INTERESTING_BACKGROUND = new Color(226, 202, 130);
        private static final Color SELECTED_OUTSIDER_BACKGROUND = new Color(112, 64, 64);

        private final ResultTableModel model;

        private ResultCellRenderer(ResultTableModel model) {
            this.model = model;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            int modelRow = table.convertRowIndexToModel(row);
            ResultSignal signal = model.signalAt(modelRow);

            if (isSelected) {
                if (signal == ResultSignal.OUTSIDER) {
                    component.setBackground(SELECTED_OUTSIDER_BACKGROUND);
                } else if (signal == ResultSignal.INTERESTING) {
                    component.setBackground(SELECTED_INTERESTING_BACKGROUND);
                } else {
                    component.setBackground(table.getSelectionBackground());
                }
                component.setForeground(table.getSelectionForeground());
                return component;
            }

            if (signal == ResultSignal.OUTSIDER) {
                component.setBackground(OUTSIDER_BACKGROUND);
            } else if (signal == ResultSignal.INTERESTING) {
                component.setBackground(INTERESTING_BACKGROUND);
            } else {
                component.setBackground(table.getBackground());
            }
            component.setForeground(table.getForeground());

            return component;
        }
    }

    private static final class EntryPointTableModel extends AbstractTableModel {
        private static final long serialVersionUID = 1L;
        private static final String[] COLUMNS = {"#", "Start", "End", "Original"};
        private final List<EntryPoint> entryPoints = new ArrayList<>();

        void add(EntryPoint entryPoint) {
            int row = entryPoints.size();
            entryPoints.add(entryPoint);
            fireTableRowsInserted(row, row);
        }

        void clear() {
            int previousSize = entryPoints.size();
            entryPoints.clear();

            if (previousSize > 0) {
                fireTableRowsDeleted(0, previousSize - 1);
            }
        }

        List<EntryPoint> entryPoints() {
            return List.copyOf(entryPoints);
        }

        Optional<EntryPoint> overlappingEntryPoint(int startInclusive, int endExclusive) {
            return entryPoints.stream()
                    .filter(entryPoint -> startInclusive < entryPoint.endExclusive()
                            && endExclusive > entryPoint.startInclusive())
                    .findFirst();
        }

        @Override
        public int getRowCount() {
            return entryPoints.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMNS[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            EntryPoint entryPoint = entryPoints.get(rowIndex);

            return switch (columnIndex) {
                case 0 -> rowIndex + 1;
                case 1 -> entryPoint.startInclusive();
                case 2 -> entryPoint.endExclusive();
                case 3 -> entryPoint.selectedText();
                default -> "";
            };
        }
    }

    private static final class ResultTableModel extends AbstractTableModel {
        private static final long serialVersionUID = 1L;
        private static final String[] COLUMNS = {"Entry", "Payload", "Status", "Length", "Signal", "Match"};
        private static final int MIN_RESULTS_FOR_SIGNAL = 8;
        private static final int MIN_STATUS_GROUP_FOR_LENGTH_SIGNAL = 5;
        private static final double RARE_STATUS_RATIO = 0.05;
        private static final double UNCOMMON_STATUS_RATIO = 0.15;
        private static final int OUTSIDER_LENGTH_MIN_DELTA = 100;
        private static final double OUTSIDER_LENGTH_RATIO = 0.35;
        private static final int INTERESTING_LENGTH_MIN_DELTA = 50;
        private static final double INTERESTING_LENGTH_RATIO = 0.15;
        private final List<FuzzResult> results = new ArrayList<>();
        private final List<ResultSignal> signals = new ArrayList<>();

        AddedRows addAll(List<FuzzResult> newResults) {
            if (newResults.isEmpty()) {
                return new AddedRows(results.size(), results.size(), List.of());
            }

            int firstRow = results.size();
            List<ResultSignal> previousSignals = new ArrayList<>(signals);
            results.addAll(newResults);
            recomputeSignals();

            List<Integer> changedSignalRows = changedSignalRows(previousSignals, firstRow);
            fireTableRowsInserted(firstRow, results.size() - 1);

            if (!changedSignalRows.isEmpty()) {
                fireTableRowsUpdated(0, firstRow - 1);
            }

            return new AddedRows(firstRow, results.size(), changedSignalRows);
        }

        void clear() {
            int previousSize = results.size();
            results.clear();
            signals.clear();

            if (previousSize > 0) {
                fireTableRowsDeleted(0, previousSize - 1);
            }
        }

        FuzzResult resultAt(int row) {
            return results.get(row);
        }

        ResultSignal signalAt(int row) {
            if (row < 0 || row >= signals.size()) {
                return ResultSignal.NORMAL;
            }

            return signals.get(row);
        }

        private void recomputeSignals() {
            signals.clear();
            for (int index = 0; index < results.size(); index++) {
                signals.add(ResultSignal.NORMAL);
            }

            if (results.size() >= MIN_RESULTS_FOR_SIGNAL) {
                LinkedHashMap<Integer, List<Integer>> rowsByEntry = new LinkedHashMap<>();
                for (int row = 0; row < results.size(); row++) {
                    rowsByEntry.computeIfAbsent(results.get(row).entryPoint(), ignored -> new ArrayList<>()).add(row);
                }

                for (List<Integer> entryRows : rowsByEntry.values()) {
                    signalEntryRows(entryRows);
                }
            }

            applyMatchSignals();
        }

        private void applyMatchSignals() {
            for (int row = 0; row < results.size(); row++) {
                if (!results.get(row).match().isBlank()) {
                    signals.set(row, stronger(signals.get(row), ResultSignal.INTERESTING));
                }
            }
        }

        private List<Integer> changedSignalRows(List<ResultSignal> previousSignals, int previousSize) {
            List<Integer> changedRows = new ArrayList<>();

            for (int row = 0; row < previousSize; row++) {
                if (row >= previousSignals.size() || previousSignals.get(row) != signals.get(row)) {
                    changedRows.add(row);
                }
            }

            return changedRows;
        }

        private void signalEntryRows(List<Integer> entryRows) {
            if (entryRows.size() < MIN_RESULTS_FOR_SIGNAL) {
                return;
            }

            LinkedHashMap<Integer, List<Integer>> rowsByStatus = new LinkedHashMap<>();
            for (int row : entryRows) {
                rowsByStatus.computeIfAbsent(results.get(row).statusCode(), ignored -> new ArrayList<>()).add(row);
            }

            int dominantStatusCount = 0;
            for (List<Integer> statusRows : rowsByStatus.values()) {
                dominantStatusCount = Math.max(dominantStatusCount, statusRows.size());
            }

            for (List<Integer> statusRows : rowsByStatus.values()) {
                ResultSignal statusSignal = statusSignal(entryRows.size(), statusRows.size(), dominantStatusCount);
                applyLengthSignals(statusRows, statusSignal);
            }
        }

        private ResultSignal statusSignal(int entryResultCount, int statusResultCount, int dominantStatusCount) {
            if (statusResultCount == entryResultCount || statusResultCount == dominantStatusCount) {
                return ResultSignal.NORMAL;
            }

            int outsiderThreshold = Math.max(1, (int) Math.floor(entryResultCount * RARE_STATUS_RATIO));
            int interestingThreshold = Math.max(3, (int) Math.floor(entryResultCount * UNCOMMON_STATUS_RATIO));

            if (statusResultCount <= outsiderThreshold) {
                return ResultSignal.OUTSIDER;
            }

            if (statusResultCount <= interestingThreshold) {
                return ResultSignal.INTERESTING;
            }

            return ResultSignal.NORMAL;
        }

        private void applyLengthSignals(List<Integer> statusRows, ResultSignal statusSignal) {
            if (statusRows.size() < MIN_STATUS_GROUP_FOR_LENGTH_SIGNAL) {
                for (int row : statusRows) {
                    signals.set(row, stronger(signals.get(row), statusSignal));
                }
                return;
            }

            int medianLength = medianLength(statusRows);

            for (int row : statusRows) {
                ResultSignal lengthSignal = lengthSignal(results.get(row), medianLength);
                signals.set(row, stronger(statusSignal, lengthSignal));
            }
        }

        private int medianLength(List<Integer> rows) {
            List<Integer> lengths = new ArrayList<>(rows.size());
            for (int row : rows) {
                lengths.add(results.get(row).responseLength());
            }

            lengths.sort(Integer::compareTo);
            int middle = lengths.size() / 2;

            if (lengths.size() % 2 == 1) {
                return lengths.get(middle);
            }

            return (int) (((long) lengths.get(middle - 1) + lengths.get(middle)) / 2);
        }

        private ResultSignal lengthSignal(FuzzResult result, int medianLength) {
            int distance = Math.abs(result.responseLength() - medianLength);
            int outsiderThreshold = Math.max(OUTSIDER_LENGTH_MIN_DELTA,
                    (int) Math.round(medianLength * OUTSIDER_LENGTH_RATIO));
            int interestingThreshold = Math.max(INTERESTING_LENGTH_MIN_DELTA,
                    (int) Math.round(medianLength * INTERESTING_LENGTH_RATIO));

            if (distance >= outsiderThreshold) {
                return ResultSignal.OUTSIDER;
            }

            if (distance >= interestingThreshold) {
                return ResultSignal.INTERESTING;
            }

            return ResultSignal.NORMAL;
        }

        private ResultSignal stronger(ResultSignal left, ResultSignal right) {
            if (left == ResultSignal.OUTSIDER || right == ResultSignal.OUTSIDER) {
                return ResultSignal.OUTSIDER;
            }

            if (left == ResultSignal.INTERESTING || right == ResultSignal.INTERESTING) {
                return ResultSignal.INTERESTING;
            }

            return ResultSignal.NORMAL;
        }

        @Override
        public int getRowCount() {
            return results.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMNS[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return switch (columnIndex) {
                case 0, 2, 3 -> Integer.class;
                default -> String.class;
            };
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            FuzzResult result = results.get(rowIndex);

            return switch (columnIndex) {
                case 0 -> result.entryPoint();
                case 1 -> result.payload();
                case 2 -> result.statusCode();
                case 3 -> result.responseLength();
                case 4 -> signalAt(rowIndex).toString();
                case 5 -> result.match();
                default -> "";
            };
        }

    }
}
