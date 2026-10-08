import path from "node:path";

// OpenCode plugin (local project plugin, auto-discovered in .opencode/plugins/).
//
// Harness glue only: it invokes the deterministic, harness-agnostic tool at
// .agentic/tools/check-framework-updates.py, interprets its JSON result and
// shows a toast when appropriate. All lock/git/commit logic lives in the tool
// — none is duplicated here.
//
// Trigger: the ONLY event handled is `session.created`. OpenCode materializes
// a session (and emits this event) when the user sends the first message; that
// is the accepted moment for the check (a TUI plugin for earlier immediacy was
// deliberately rejected to avoid managing shared OpenCode config). Child
// sessions and subagents (info.parentID set) are ignored: only primary sessions
// trigger a check. No other event (e.g. server.connected) is used and no check
// runs during plugin initialization.
//
// Throttling (in-memory only, per loaded plugin instance / per repo; resets
// when OpenCode restarts — there is no on-disk persistence):
//   * MIN_CHECK_INTERVAL_MS — at most one remote check per hour. lastCheckAt
//     records when an attempt STARTED (success or failure), so a network
//     failure does not cause a retry on every new session.
//   * NOTIFY_DEDUP_INTERVAL_MS — the same update (same remote_commit) is
//     notified at most once every 24h. A different remote_commit can notify on
//     the next hourly check even if <24h elapsed since the previous notice.
//   * DIAGNOSTIC_DEDUP_INTERVAL_MS — each diagnostic key (LOCK_MISSING,
//     LOCK_INCOMPLETE, LOCK_INVALID, REMOTE_BRANCH_MISSING, GIT_OR_NETWORK_ERROR,
//     TOOL_EXECUTION_ERROR) is notified at most once every 24h, INDEPENDENTLY.
//     A Map (diagnosticNotificationAtByKey) keeps a per-key timestamp so
//     alternating diagnostics never reset each other's throttle.
//
// Concurrency: a single in-flight check is enforced. lastCheckAt and
// checkInFlight are set synchronously before the check is detached, so two
// session.created events fired back-to-back (or a primary plus a subagent
// during the same check) start at most one tool. checkInFlight is cleared in a
// `finally` so an exception can never leave it stuck.
//
// The check is fire-and-forget: the handler does not await it, so the session
// is never delayed by the (bounded) remote check. Toast display is best-effort:
// a toast failure propagates to runCheck and is swallowed by the top-level
// `.catch`, leaving the session untouched.
//
// `now` is an optional injectable clock (tests use it for deterministic time);
// production leaves it undefined and Date.now is used.

const TOOL_REL = path.join(".agentic", "tools", "check-framework-updates.py");

const MIN_CHECK_INTERVAL_MS = 60 * 60 * 1000; // 1 hour
const NOTIFY_DEDUP_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours
const DIAGNOSTIC_DEDUP_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

function shortSha(sha) {
  // Show short SHAs in toasts for legibility; the tool still compares full SHAs.
  return typeof sha === "string" && sha.length >= 12 ? sha.slice(0, 12) : String(sha);
}

// Build the manual update instructions. When the tool surfaces framework_source
// (the local path used by the last apply), make the pull step concrete;
// otherwise keep it generic. source is only an informational hint, never a
// trusted origin.
//
// The sync command must be run FROM the framework clone (it resolves the
// framework root as the script's grandparent), not from the target repo. The
// plugin does not have a reliable absolute path for the target, so it instructs
// the user to indicate it rather than fabricating one.
const APPLY_CMD = "python3 bin/agentic-sync.py --apply";

function pullStep(frameworkSource) {
  if (frameworkSource) {
    return "Actualiza el clon local del framework en " + frameworkSource +
      " con git pull --ff-only.";
  }
  return "Actualiza primero tu clon local del Agentic Framework con " +
    "git pull --ff-only.";
}

function applyStep() {
  // No trailing period: callers compose further text (a trailing sentence for
  // LOCK_INCOMPLETE, or the closing period for the other states).
  return "Despues, desde ese clon, ejecuta " + APPLY_CMD +
    " indicando la ruta de este repositorio";
}

function buildToast(r) {
  // Returns the toast payload to show, or null when the state must be silent.
  switch (r.code) {
    case 0: // UP_TO_DATE
      return null;
    case 2: // SOURCE_REPO_SKIPPED
      return null;
    case 1: // UPDATE_AVAILABLE
      return {
        title: "Actualizacion del framework disponible",
        message:
          "Instalado: " + shortSha(r.installed_commit) + "\n" +
          "Disponible: " + shortSha(r.remote_commit) + "\n" +
          "Rama: " + r.branch + "\n\n" +
          pullStep(r.framework_source) + " " + applyStep() + ".",
        variant: "warning",
        duration: 12000,
      };
    case 3: // LOCK_MISSING
      return {
        title: "Framework incompleto",
        message:
          "Falta .agentic.lock.json; la instalacion o sincronizacion esta " +
          "incompleta. " + pullStep(r.framework_source) + " " + applyStep() + ".",
        variant: "warning",
        duration: 10000,
      };
    case 4: // LOCK_INCOMPLETE
      return {
        title: "Framework incompleto",
        message:
          "El lock no contiene todavia la trazabilidad necesaria. " +
          pullStep(r.framework_source) + " " + applyStep() +
          " para regenerar el lock.",
        variant: "warning",
        duration: 10000,
      };
    case 5: // LOCK_INVALID
    case 6: // REMOTE_BRANCH_MISSING
    case 7: // GIT_OR_NETWORK_ERROR
      return {
        title: "No se pudo comprobar el framework",
        message: "No se pudo comprobar el estado de actualizacion del framework.",
        variant: "info",
        duration: 6000,
      };
    default:
      return null;
  }
}

// Toast shown when the tool itself could not be executed or its output was not
// valid JSON. Uses a stable diagnostic key (TOOL_EXECUTION_ERROR) so it is
// throttled like the tool's own error states.
const EXEC_ERROR_TOAST = {
  title: "No se pudo comprobar el framework",
  message: "No se pudo comprobar el estado de actualizacion del framework.",
  variant: "info",
  duration: 6000,
};

async function showToast(client, toast) {
  if (!toast) return;
  // Best-effort: a rejection propagates to runCheck, which clears checkInFlight
  // in its `finally` and is then swallowed by the top-level `.catch`. The
  // session is never affected by a toast failure.
  await client.tui.showToast({ body: toast });
}

function makeInitialState() {
  return {
    // When the last check attempt STARTED (success or failure). Hourly throttle.
    lastCheckAt: null,
    // True while a check is running. Guards against concurrent tool launches.
    checkInFlight: false,
    // remote_commit of the last update shown. Daily dedup identity.
    lastNotifiedCommit: null,
    // When the last update toast was shown. Daily dedup clock.
    lastNotificationAt: null,
    // Per-diagnostic-key timestamp of the last toast. Each key keeps its own
    // clock so alternating diagnostics never reset each other's 24h throttle.
    diagnosticNotificationAtByKey: new Map(),
  };
}

async function maybeNotifyDiagnostic(client, state, now, key, toast) {
  if (!toast) return;
  const t = now();
  const last = state.diagnosticNotificationAtByKey.get(key);
  if (last !== undefined && (t - last) < DIAGNOSTIC_DEDUP_INTERVAL_MS) return;
  await showToast(client, toast);
  // Record only after a successful display.
  state.diagnosticNotificationAtByKey.set(key, now());
}

async function handleResult(client, r, state, now) {
  const code = (r && typeof r.code === "number") ? r.code : null;
  switch (code) {
    case 0: // UP_TO_DATE — silent
    case 2: // SOURCE_REPO_SKIPPED — silent
      return;
    case 1: { // UPDATE_AVAILABLE
      const remote = r.remote_commit;
      const t = now();
      // Notify when: never notified before; OR remote_commit differs from the
      // last notified one; OR same commit but >= 24h since the last notice.
      // A new commit therefore notifies on the next hourly check even if <24h
      // have passed since the previous (different) notice.
      const neverNotified = state.lastNotifiedCommit === null;
      const differentCommit = state.lastNotifiedCommit !== remote;
      const dueDaily = state.lastNotificationAt === null ||
                       (t - state.lastNotificationAt) >= NOTIFY_DEDUP_INTERVAL_MS;
      if (!(neverNotified || differentCommit || dueDaily)) return;
      await showToast(client, buildToast(r));
      // Record only after a successful display.
      state.lastNotifiedCommit = remote;
      state.lastNotificationAt = now();
      return;
    }
    case 3: // LOCK_MISSING
    case 4: // LOCK_INCOMPLETE
    case 5: // LOCK_INVALID
    case 6: // REMOTE_BRANCH_MISSING
    case 7: { // GIT_OR_NETWORK_ERROR
      // The tool's `status` string is the stable diagnostic key. Fall back to
      // TOOL_EXECUTION_ERROR only if status is unexpectedly absent.
      const key = (r && typeof r.status === "string" && r.status.length)
        ? r.status : "TOOL_EXECUTION_ERROR";
      await maybeNotifyDiagnostic(client, state, now, key, buildToast(r));
      return;
    }
    default:
      return;
  }
}

async function runCheck(client, $, worktree, sessionDirectory, state, now) {
  try {
    const toolPath = path.join(worktree || "", TOOL_REL);
    const rootDir = sessionDirectory || worktree || "";

    // Execute the tool without a shell, capturing stdout/stderr/exitCode. The
    // tool contract is unchanged: `python3 <tool> --root <root>`. No git/lock
    // logic is duplicated here; the tool owns it all and never writes files.
    let parsed = null;
    let execError = false;
    try {
      const res = await $`python3 ${toolPath} --root ${rootDir}`.quiet().nothrow();
      parsed = JSON.parse(String(res.stdout).trim());
    } catch (_e) {
      execError = true;
    }

    if (execError || !parsed) {
      await maybeNotifyDiagnostic(
        client, state, now, "TOOL_EXECUTION_ERROR", EXEC_ERROR_TOAST,
      );
      return;
    }

    await handleResult(client, parsed, state, now);
  } finally {
    // ALWAYS release the in-flight slot, even if an exception escaped the inner
    // try or handleResult. This guarantees a transient failure cannot lock out
    // future checks permanently.
    state.checkInFlight = false;
  }
}

export const AgenticUpdateCheck = async ({ client, $, worktree, now }) => {
  // Injectable clock: tests pass a controllable `now`; production omits it and
  // Date.now is used. This does not change the public signature for OpenCode.
  const clock = typeof now === "function" ? now : () => Date.now();
  const state = makeInitialState();

  return {
    event: async ({ event }) => {
      // 1. Confirm the event is really session.created.
      if (!event || event.type !== "session.created") return;

      // 2. Obtain the session via the SDK's official event shape:
      //    EventSessionCreated = { type, properties: { info: Session } }.
      const info = event.properties && event.properties.info;
      if (!info || !info.id) return;

      // 3/4. Ignore child sessions and subagents: a session with a non-empty
      // parentID is not primary and must never trigger a check.
      if (info.parentID && String(info.parentID).length > 0) return;

      // 5. If a check is already in progress, do nothing — no second tool, no
      // duplicate notifications.
      if (state.checkInFlight) return;

      // 6. Hourly throttle: at most one remote check per hour. lastCheckAt
      // records the start of the last attempt, so a failure does not retry on
      // every new session.
      const t = clock();
      if (state.lastCheckAt !== null &&
          (t - state.lastCheckAt) < MIN_CHECK_INTERVAL_MS) {
        return;
      }

      // Claim the slot synchronously BEFORE detaching the check, so two events
      // fired back-to-back start at most one tool.
      state.lastCheckAt = t;
      state.checkInFlight = true;

      // 7. Fire-and-forget: run the tool once. The handler resolves
      // immediately; the session is not delayed by the remote check.
      void runCheck(client, $, worktree, info.directory, state, clock).catch(() => {});
    },
  };
};
