# Design prompt: one code tool, the model builds its own tooling

A portable, domain- and language-agnostic prompt. Paste the block between the
`---` markers into another project's coding agent to shape how that project
exposes itself to a model. Fill in the placeholders at the top of the block;
nothing in it is specific to any one project, language, or transport. (A working
reference implementation lives in this repository — the single tool, its
persistent-namespace harness, and the tests for both — if your agent has access
to it.)

---

You are changing how **`<PROJECT>`** exposes itself to a model — its tool
surface, whether that is an MCP server, a function-calling tool set, or any other
tool host. Apply the design below. It is a contract, not a style suggestion:
implement it faithfully and do not reintroduce the patterns it replaces.

Placeholders to resolve before you start:
- `<PROJECT>` — the repo / server you are changing.
- `<DOMAIN_API>` — the project's real capability objects the model should drive
  (its sessions / clients / connections / services and their methods). List the
  actual objects and how one is created.
- `<TOOL_NAME>` — the single tool's name (default `run`, or a short verb/noun
  that fits the project).
- `<HOST_LANG>` — the language the tool executes (the project's own; e.g. the
  language its API is written in).
- `<PERSIST_LOCATION>` — where kept definitions are stored (a configurable path,
  default a per-project directory under the user's home/config dir).

## Why (the thesis — keep this in mind, don't just mechanically comply)

A fixed catalog of typed tools is the wrong interface. Every target / version /
install supports a different subset of capabilities, and **different models have
different tools available and perform differently with them** — so hand-picking
one menu of verbs biases the system toward some models and some targets, and
every new capability needs new hand-wired glue. Instead, expose **one tool that
runs code**, and let the model **build its own tooling** on top of a live API:
discover what's there, write helpers, reuse and refine them. The harness adapts
to the model and the task, not the other way round. (Same core idea as "code
mode" / "tools as code": fewer composable primitives beat a large static tool
schema.)

## What to build

1. **One tool, and only one.** Advertise exactly `<TOOL_NAME>` and nothing else.
   It takes a single `code` argument, plus — only if the domain needs them — an
   optional target selector (e.g. a session/connection id) and an optional map of
   named strings. If the project already advertises a catalog of per-capability
   verbs, stop advertising them (keep them, see 7); if it doesn't, do not add
   one. The argument is *code*, not a command selector — no `action`/verb
   dispatcher.

2. **The tool runs `<HOST_LANG>` code in ONE long-lived namespace.** Definitions
   and variables the model creates **persist across calls** for the life of the
   process. Each call optionally binds the working object(s) named by the target
   selector, runs the code, and returns whatever the code printed plus its last
   value (the language's natural last-expression result, or an assigned result
   variable).

3. **Everything is reached from inside that namespace as functions/objects — not
   as separate tools.** Seed the namespace with:
   - the project's `<DOMAIN_API>` entry points: a way to list what the project
     offers, a way to create/open a working object, a way to bind an existing one;
   - `describe(x)` — for a working object, its **live capabilities** and every
     method's **signature + one-line doc** via the language's introspection
     (fall back to a doc comment / first line for native/compiled methods); for
     any object, its public members;
   - the bound working object(s) themselves, so the model drives the full API in
     code (no verb-per-method);
   - a way to pass long/literal text (payloads, code, blobs) as named values
     instead of escaping it inside `code`;
   - `kept()` / `forget(name)` and a `man()` manual function.

4. **Definitions persist across restarts.** After a successful call, write each
   top-level *definition* (function/class/constant — detected via the language's
   AST or equivalent, one unit per bound name) to `<PERSIST_LOCATION>`. At
   startup, load each saved unit back into the namespace, each isolated so a
   broken one cannot stop the server from starting. Persist **only** definitions,
   never side-effecting statements (actual work), so a restart rebuilds the
   model's tools without replaying work. Provide `forget(name)` to delete one.

5. **Discovery is in-language.** Calling the tool with empty `code` returns the
   manual: what the namespace provides, how to create a working object, and what
   the project offers. The model bootstraps from that, then `describe(...)` a
   working object to see its real surface.

6. **Security is a deployment fact, not a toggle.** Running code *is* what the
   tool is — it executes with the server's authority — so there is **no
   enable/disable knob and no "default" to reason about**: the tool always runs
   code, and the server is meant to be run sandboxed (a container/VM/jail). Say
   that plainly and prominently in the tool description, the server instructions
   and the README. Do not add an enable/disable flag; a flag reframes the design
   as an optional feature, which it is not.

7. **Keep the old capability code, don't advertise it.** Leave any pre-existing
   per-capability functions in place (the harness and tests call them) but do
   **not** register them as tools and do **not** add a flag to advertise them.
   The only registered tool is `<TOOL_NAME>`. Register just that one name (a thin
   shim over whatever tool-registration mechanism the host uses is enough, so you
   needn't touch every existing function). Capabilities are reached from code
   (`working_object.method(...)`), not as verbs.

8. **Wrap any other tool sources as callable functions** in the namespace where
   applicable (the "tools as code" move) — other MCP servers, HTTP APIs, CLIs —
   rather than re-advertising them as separate tools.

## Acceptance criteria (write tests for these)

- The advertised tool set is exactly `{<TOOL_NAME>}` — one tool, unconditionally.
- Empty `code` returns a manual that names the namespace vocabulary and what the
  project offers.
- A helper defined in one call is reusable in the **next** call without being
  redefined.
- A definition made in one process is reloaded and usable in a **fresh process**
  pointed at the same `<PERSIST_LOCATION>` (prove restart persistence), and
  `forget(name)` removes it.
- Any pre-existing capability code still works when driven from `code`.
- Tests isolate `<PERSIST_LOCATION>` to a throwaway path so they never touch a
  real user directory.

## Do not

- Do not ship a parallel structured/`action=` interface, nor a typed-verb
  catalog, nor an enable/disable or expose-tools flag. Each of those reframes the
  one code tool as an optional feature layered on something else; it is the
  interface, full stop. Safe deployment is sandboxing the server, not a
  code-free tool mode.
- Do not delete the underlying capability code; just don't register it as tools.
- Do not per-branch the tool set on model identity — adaptation is emergent
  (each deployment's model accretes its own helpers), not a per-model switch.
