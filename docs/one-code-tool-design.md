# Design prompt: one code tool, the model builds its own tooling

A portable, domain-agnostic prompt. Paste the block between the `---` markers
into another project's coding agent to refactor that project's MCP server to
this design. Fill in the four placeholders at the top of the block; nothing in
the block is specific to any one project. (A working reference implementation
lives in this repository — the single tool, its persistent-namespace harness,
and the tests for both — if your agent has access to it.)

---

You are refactoring the MCP server in **`<PROJECT>`**. Change its tool surface
to the design specified below. Do not treat this as a style suggestion — it is a
contract; implement it faithfully and do not reintroduce the patterns it
replaces.

Placeholders to resolve before you start:
- `<PROJECT>` — the repo / server you are changing.
- `<DOMAIN_API>` — the project's real capability objects the model should drive
  (its sessions / clients / connections / services and their methods). List the
  actual objects and how one is created.
- `<TOOL_NAME>` — the single tool's name (default `run`, or a short verb/noun
  that fits the project).
- `<ENV_PREFIX>` — uppercase env-var prefix (default: the project name).

## Why (the thesis — keep this in mind, don't just mechanically comply)

A fixed catalog of typed tools is the wrong interface. Every target / version /
install supports a different subset of capabilities, and **different models have
different tools available and perform differently with them** — so hand-picking
one menu of verbs biases the system toward some models and some targets, and
every new capability needs new hand-wired glue. Instead, expose **one tool that
runs code**, and let the model **build its own tooling** on top of a live API:
discover what's there, write helpers, reuse and refine them. The harness adapts
to the model and the task, not the other way round. (Same core idea as "code
mode" / "MCP tools as code": fewer composable primitives beat a large static
tool schema.)

## What to build

1. **One tool, and only one.** Advertise exactly `<TOOL_NAME>(code: str = "",
   session_id: str = "", strings: dict | None = None) -> str` and nothing else.
   Remove the catalog of per-capability verbs from what is advertised. Do not add
   an `action`/verb dispatcher — the parameter is *code*, not a command selector.

2. **The tool runs code in ONE long-lived namespace.** Definitions and variables
   the model creates **persist across calls** for the life of the process. Each
   call binds the current working object(s) for the given `session_id`, runs the
   code, and returns captured stdout plus the value of a trailing expression
   (REPL-style), or an assigned `result`.

3. **Everything is reached from inside that namespace as functions/objects — not
   as separate tools.** Seed the namespace with:
   - the project's `<DOMAIN_API>` entry points: a way to list what the project
     offers, a way to create/open a working object, a way to bind an existing one;
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
   top-level *definition* (function/class/assignment — parse the source with an
   AST, one file per bound name) to `<ENV_PREFIX>_HARNESS_DIR` (default
   `~/.<project>/harness`). At startup, load each saved file back into the
   namespace, each in its own try/except so a broken saved definition cannot
   stop the server from booting. Do **not** persist side-effecting statements
   (actual work) — only definitions, so a restart rebuilds the model's tools
   without replaying work. Provide `forget(name)` to delete one.

5. **Discovery is in-language.** Calling the tool with empty `code` returns the
   manual: what the namespace provides, how to create a working object, and what
   the project offers. The model bootstraps from that, then `describe(...)` a
   working object to see its real surface.

6. **Security is a deployment fact, not a toggle.** Running code *is* what the
   tool is — it executes with the server's authority — so there is **no
   enable/disable knob and no "default" to reason about**: the tool always runs
   code, and the server is meant to be run sandboxed (a container/VM). Say that
   plainly and prominently in the tool description, the server instructions and
   the README. Do not add an enable/disable flag; a flag reframes the design as
   an optional feature, which it is not.

7. **Keep the old capability functions, don't advertise them.** Leave the
   project's existing per-capability functions defined in the module (the harness
   and tests call them) but do **not** register them as MCP tools and do **not**
   add a flag to advertise them. The only registered tool is `<TOOL_NAME>`.
   Implement this as a thin shim over the tool decorator that registers only that
   one name, so you don't have to edit every existing function. Capabilities are
   reached from code (`working_object.method(...)`), not as verbs.

8. **Wrap existing MCP servers / tools as callable functions** in the namespace
   where applicable (the "tools as code" move), rather than re-advertising them.

## Acceptance criteria (write tests for these)

- The advertised tool set is exactly `{<TOOL_NAME>}` — one tool, unconditionally.
- Empty `code` returns a manual that names the namespace vocabulary and what the
  project offers.
- A helper defined in one call is reusable in the **next** call without being
  redefined.
- A definition made in one process is reloaded and usable in a **fresh process**
  pointed at the same `<ENV_PREFIX>_HARNESS_DIR` (prove restart persistence),
  and `forget(name)` removes it.
- The pre-existing capability functions still work when driven from code.
- Tests isolate `<ENV_PREFIX>_HARNESS_DIR` to a temp dir so they never touch a
  real home directory.

## Do not

- Do not ship a parallel structured/`action=` interface, nor a typed-verb
  catalog, nor an enable/disable or expose-tools flag. Each of those reframes the
  one code tool as an optional feature layered on something else; it is the
  interface, full stop. Safe deployment is sandboxing the server, not a
  code-free tool mode.
- Do not delete the underlying capability functions; just don't register them as
  tools.
- Do not per-branch the tool set on model identity — adaptation is emergent
  (each deployment's model accretes its own helpers), not a per-model switch.
