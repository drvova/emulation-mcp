# Design prompt: one code tool, the model builds its own tooling

Paste the block below into another project's coding agent to have it refactor
that project's MCP server to the same system design this repo (`emulation-mcp`,
the `emu` tool) uses. It is domain-agnostic — fill in the four placeholders at
the top and delete this header.

---

You are refactoring the MCP server in **`<PROJECT>`**. Change its tool surface
to the design specified below. Do not treat this as a style suggestion — it is a
contract; implement it faithfully and do not reintroduce the patterns it
replaces.

Placeholders to resolve before you start:
- `<PROJECT>` — the repo / server you are changing.
- `<DOMAIN_API>` — the project's real capability objects the model should drive
  (e.g. sessions/clients/connections/engines and their methods). List the actual
  objects and how one is created.
- `<TOOL_NAME>` — the single tool's name (default: `run`, or the project's short
  noun; this repo uses `emu`).
- `<ENV_PREFIX>` — uppercase env-var prefix (default: the project name).

## Why (the thesis — keep this in mind, don't just mechanically comply)

A fixed catalog of typed tools is the wrong primary interface. Every
backend/version/install supports a different subset of capabilities, and
**different models have different tools available and perform differently with
them** — so hand-picking one menu of verbs biases the system toward some models
and some backends, and every new capability needs new hand-wired glue. Instead,
expose **one tool that runs code**, and let the model **build its own tooling**
on top of a live API: discover what's there, write helpers, reuse and refine
them. The harness adapts to the model and the task instead of the other way
round. (Same core idea as "code mode" / "MCP tools as code": fewer, composable
primitives beat a large static tool schema.)

## What to build

1. **Advertise exactly ONE tool by default**, `<TOOL_NAME>(code: str = "",
   session_id: str = "", strings: dict | None = None) -> str`. Remove (stop
   advertising) the catalog of per-capability verbs. Do not add an `action`/verb
   dispatcher — the parameter is *code*, not a command selector.

2. **The tool runs Python (or the host language) in ONE long-lived namespace.**
   Definitions and variables the model creates **persist across calls** for the
   life of the process. Each call binds the current working object(s) for the
   given `session_id`, runs the code, and returns captured stdout plus the value
   of a trailing expression (REPL-style), or an assigned `result`.

3. **Everything is reached from inside that namespace as functions/objects — not
   as separate tools.** Seed the namespace with:
   - the project's `<DOMAIN_API>` entry points: a way to list what backends/
     capabilities exist, a way to create/open a working object, a way to bind an
     existing one;
   - `describe(x)` — for a working object, its **live capabilities** and every
     method's **signature + one-line doc** (use `inspect.signature`, falling back
     to the first docstring line for native/compiled methods); for any object,
     its public members;
   - the bound working object(s) themselves, so the model drives the full API in
     code (no verb-per-method);
   - `S` — the `strings` dict the caller passed, so long/literal text (payloads,
     code, blobs) is passed as named strings instead of being escaped inside
     `code`;
   - `kept()` / `forget(name)` and a `man()` manual function.

4. **Definitions persist across restarts.** After a successful call, write each
   top-level *definition* (function/class/assignment — parse with `ast`, one
   file per bound name) to `<ENV_PREFIX>_HARNESS_DIR` (default
   `~/.<project>/harness`). At startup, exec each saved file back into the
   namespace, each in its own try/except so a broken saved definition cannot
   stop the server from booting. Do **not** persist side-effecting statements
   (actual work) — only definitions, so a restart rebuilds the model's tools
   without replaying work. Provide `forget(name)` to delete one.

5. **Discovery is in-language.** Calling the tool with empty `code` returns the
   manual: what the namespace provides, how to create a working object, and the
   list of available backends/capabilities. The model bootstraps from that, then
   `describe(...)` a working object to see its real surface.

6. **Security posture (state it loudly, make it reversible).** This runs
   arbitrary code with the server's authority. It is the primary interface, so
   it is **ON by default** — and the tool description, server instructions and
   README must say, prominently, to **run the server sandboxed (a container/VM)**.
   Provide `<ENV_PREFIX>_DISABLE_CODE=1` to turn it off; when off, the tool
   returns a clear message pointing at the escape hatch in (7). (If the project
   must default to off for policy reasons, keep the one tool and this switch;
   just invert the default and say so.)

7. **Optional typed-catalog escape hatch.** Keep the old typed functions defined
   in the module (do not delete them) but **do not advertise them** unless
   `<ENV_PREFIX>_EXPOSE_TYPED_TOOLS=1` is set. This serves locked-down
   deployments (disable code, expose explicit verbs) and clients/models that
   prefer discoverable schemas. Implement the gate as a thin shim over the tool
   decorator keyed on an always-on set `{<TOOL_NAME>}`, so you don't edit every
   existing tool definition.

8. **Wrap existing MCP servers / tools as callable functions** in the namespace
   where applicable (the "tools as code" move), rather than re-advertising them.

## Acceptance criteria (write tests for these)

- Default advertised tool set is exactly `{<TOOL_NAME>}`; with
  `<ENV_PREFIX>_EXPOSE_TYPED_TOOLS=1` the full catalog is advertised alongside it.
- Empty `code` returns a manual that names the namespace vocabulary and lists
  backends/capabilities.
- A helper defined in one call is reusable in the **next** call without being
  redefined.
- A definition made in one process is reloaded and usable in a **fresh process**
  pointed at the same `<ENV_PREFIX>_HARNESS_DIR` (prove restart persistence),
  and `forget(name)` removes it.
- With code disabled, the tool refuses clearly and names the escape hatch.
- The pre-existing capability tests still pass (the typed functions remain
  importable/callable even when unadvertised).
- Tests isolate `<ENV_PREFIX>_HARNESS_DIR` to a temp dir so they never touch a
  real home directory.

## Do not

- Do not ship a parallel structured/`action=` interface "for safety" — that is
  the divergence this design removes. Safe, code-free use is the typed-catalog
  flag in (7), not a second code-free dispatcher baked into the one tool.
- Do not delete the underlying capability functions; only stop advertising them.
- Do not per-branch the tool set on model identity — adaptation is emergent
  (each deployment's model accretes its own helpers), not a per-model switch.

## Reference implementation

`emulation-mcp`'s `emu` tool realizes this exactly: `server.py` (`emu`,
`_harness_ns`, `_run_harness`, `_persist_definitions`, `_load_persisted`, the
`_gated_tool` shim) and `tests/test_server.py` (`TestToolSurface`). Mirror its
shape, substituting your `<DOMAIN_API>` for the emulation engines.
