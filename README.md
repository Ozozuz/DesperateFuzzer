# DesperateFuzzer

Burp Suite extension for the noble moment when the methodology reaches:

```text
E mo che posso fare?
Non ho altre idee.
```

So you fuzz the thing and hope the application explains itself by breaking.

<img src="assets/desperate-fuzzer-meme.jpg" alt="DesperateFuzzer trade offer meme" width="320">

## What It Does

- Turns "I have no more ideas" into hundreds of requests and a mild sense of purpose.
- Sends raw, encoded, chained-encoded, or mutation-based payloads into whatever parameter looks guilty.
- Lets you stack encodings until the backend starts questioning its career choices.
- Highlights weird results, because apparently reading 256 almost-identical rows is a personality flaw.
- Keeps the full request/response around, so your future self can still pretend this was a controlled experiment.
- Mutation mode starts from something valid and makes it worse with confidence.
- Fuzzes HTTP requests and WebSocket text or binary messages.
- Adapts concurrency and pacing when the target slows down or starts failing.
- Accepts HTTP requests directly from Proxy interception/history or Repeater through Burp's context menu.

Encoding chains are intentionally stackable:

```text
empty pipeline = plain/raw
url -> url
base64 -> url
```

## Adaptive Speed Profiles

The five built-in profiles use concrete limits. They are ceilings rather than promises: an adaptive controller tracks an exponentially weighted response-time and failure average, then reduces concurrency and request rate when the target moves above the profile's latency target.

```text
Profile       Concurrent   Max req/s   Latency target   Response timeout
Stealth                1           1          1200 ms           10000 ms
Conservative           2           4          1000 ms            8000 ms
Balanced               6          15           800 ms            6000 ms
Fast                   12          40           600 ms            5000 ms
Aggressive             24         100           400 ms            3000 ms
```

`Custom` exposes the same four controls in the extension UI. `Balanced` is the default. The results table includes response time, and unusually slow results can be promoted to `interesting` or `outsider` alongside status, length, and error-signature signals.

## WebSocket Fuzzing

There are two ways to prepare a WebSocket run:

1. In Burp's WebSocket history/editor, right-click a message and choose **Send WebSocket message to DesperateFuzzer**. This preserves the original upgrade request, including cookies and custom headers.
2. Enter a `ws://` or `wss://` target including its path and paste a message manually. The default **Auto** transport detects the scheme and performs the WebSocket upgrade automatically.

Choose a text or binary frame, select bytes in the message, add the entry point, then run ASCII or mutation fuzzing as usual. Each case uses an isolated WebSocket connection so asynchronous messages from concurrent cases cannot be attributed to the wrong payload. The first application message received after sending the case is recorded as its response; the profile timeout handles endpoints that do not reply.

Transport selection follows the target scheme in **Auto** mode: `http://` and `https://` use HTTP, while `ws://` and `wss://` create a WebSocket and issue the upgrade handshake. Explicit HTTP/WebSocket overrides remain available for validation and troubleshooting.

## Metamorphic Engine

Mutation runs remain deterministic and bounded to 512 unique cases per entry point. In addition to boundary values, byte/bit flips, arithmetic changes, interesting bytes, block operations, and deterministic havoc, the engine now derives structure-aware relations such as:

- case, whitespace, quoting, array/object wrapping, duplication, and reversal;
- numeric predecessor/successor, negation, leading-zero, and exponent forms;
- JSON property injection and path separator/traversal variants.

Mutation seeds and generated payloads are size-capped to avoid runaway memory use. Positional token replacement preserves the surrounding seed bytes.

## How Signals Are Chosen

The `Signal` column exists because scrolling through hundreds of identical-looking responses is not a personality test anyone should have to pass.

Every result starts as normal. Then DesperateFuzzer gets suspicious in four ways:

- **Status rarity**: results are grouped by entry point, then by HTTP status. A lonely `500` in a sea of `200`s is an `outsider`; a small but not microscopic status group is `interesting`. Revolutionary concept: different status codes may mean different things.
- **Length drift**: lengths are compared only inside the same entry point and same status group. A weird `200` is compared with other `200`s, not with redirects, because chaos is not a baseline. Big body-size deviations become `outsider`; moderate ones become `interesting`.
- **Error signatures**: the response body is grepped for boringly useful leaks like `ORA-00933`, `SQLSTATE`, Java/Python/.NET/PHP stack traces, Spring internals, Go panics, and debug-page classics. A match promotes the row to at least `interesting`, because if the app prints a stack trace, it is probably trying to confess.
- **Timing drift**: response times are compared within the same entry point and status group. Slow responses are highlighted only when they exceed both an absolute and relative threshold, avoiding noise from naturally slow endpoints.

The `Match` column shows which explicit error/debug signature was found. This never downgrades a stronger signal: if a row is already an `outsider`, finding a stack trace does not politely demote it to "mildly spicy".

## Build

Requires JDK 17+ and `lib/montoya-api-2026.4.jar`.

```bash
./scripts/build.sh
```

Load this in Burp:

```text
build/libs/DesperateFuzzer-0.2.2.jar
```
