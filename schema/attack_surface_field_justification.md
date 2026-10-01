# Rationale for the Attack-Surface Schema Fields

## Research basis

The schemas model three connected views of the attack surface:

1. **L1: concrete interactions** such as routes, streams, and tool calls.
2. **L2: business operations** that may span several interactions or produce effects beyond an API response.
3. **Agent runtime:** agents, tools, context, memory, execution paths, and controls.

This separation is well motivated. OWASP defines attack-surface analysis around paths for data and commands into and out of an application, plus the code that protects those paths. Its threat-modeling guidance also calls for showing processes, data stores, data flows, external entities, and trust boundaries.[^1][^2] These ideas support linked inventories and cross-references, though the sources do not prescribe the exact field names or enum values used here.

## Why the field groups fit

| Schema area | Rationale |
|---|---|
| **L1 interaction identity and shape** — `id`, `component`, `direction`, `interaction_type`, `method`, `path`, `ui_trigger`, `parameters` | These fields record where an interaction occurs, how it is invoked, and what data crosses the boundary. Distinguishing HTTP routes from MCP and agent tool calls captures their different invocation and parameter models. `ui_trigger` records how an interaction may be discovered. This follows OWASP’s emphasis on cataloguing entry and exit paths, including APIs, UI fields, files, and messages.[^1] |
| **L1 access and conditions** — `auth_requirement`, `authz_check_location`, `state_preconditions`, `controls_observed` | A nominal role or session requirement does not show whether authorization is checked for the specific action or object. OWASP notes that object-level checks can be missed at individual endpoints, with consequences including disclosure, modification, or deletion. Recording where checks happen and what other state is required helps reviewers assess the actual access path.[^3] |
| **Discovery, runtime access, and evidence** — `visibility`, `reachability`, `evidence`, `source_ref`, `evidence_status`, `notes` | These fields distinguish whether a surface can be found from whether it can be exercised in a particular deployment, and whether a claim came from a live observation, source inspection, or inference. This is useful for gated routes, disabled features, and tools that exist in source but are not connected to an agent. The exact labels are a schema design choice; the sources support maintaining an accurate, reviewable inventory rather than prescribing this taxonomy.[^1][^2] |
| **L2 business meaning and assets** — `semantic_operation`, `business_objects`, `realizing_l1_ids`, `preconditions` | A single endpoint can support different business operations, and one operation can involve several endpoints. Naming the operation and its business objects supports misuse analysis even when each individual request appears valid. OWASP’s business-logic guidance asks reviewers to follow the process, identify valuable outcomes, and consider skipped, repeated, or out-of-order steps.[^4] |
| **L2 data movement and effects** — `parameter_flow`, `effect_state_transition` | A per-hop trace shows where a value came from, how it was transformed, and which component or consumer received it. Recording the resulting state change captures consequences such as database writes, messages sent, or memory updates that may not be visible in the HTTP response. This matters when untrusted content can affect model behavior or downstream actions: OWASP describes prompt injection leading to sensitive-data disclosure, unauthorized function use, and actions in connected systems.[^5] |
| **Agent identity and instructions** — `agent_kind`, `purpose`, `invocation_surfaces`, `model_config`, `instruction_sources`, `authority_context` | The runtime’s role, decision authority, model configuration, prompt sources, and effective identity affect what it can do and how reproducible its behavior is. OWASP identifies excessive functionality, permissions, and autonomy as causes of excessive agency, and recommends least privilege, user-scoped authorization, and approval for high-impact actions. System prompts should not be treated as authorization controls or as a safe place for secrets.[^6][^7] |
| **Tool bindings** — capability, source, argument schema and handling, effect class, approval, authority scope | These fields describe the agent’s practical permissions and side effects, not just a tool’s name. They help identify whether a tool can read, write, send, spend, or delete, and whether its arguments and authorization are checked. MCP describes tools as model-controlled executable functions; its tool-annotation guidance also emphasizes that behavior hints are not enforcement.[^8][^9] |
| **Context sources and memory** — provenance, destination, channel, trust, transformations, persistence; plus memory readers, writers, scope, provenance, and retention | Agent input may include user text, tool results, retrieved documents, history, and delegated summaries. Tracking origin, trust, transformation, and retention helps reviewers find indirect prompt injection, persistent poisoning, and cross-tenant disclosure paths. OWASP describes risks from external or manipulated content and from shared vector stores, including context leakage between tenants.[^5][^10] |
| **Execution edges and controls** — decision maker, conditions, argument sources, approvals, execution mode, failure behavior; and control stage, mode, implementation, and failure mode | These fields make action paths reviewable: who or what selects a transition, what influences it, whether it is queued or retried, and what happens when a check fails. OWASP identifies unsafe downstream handling of model output and excessive consumption as risks. Recording whether a safeguard blocks, modifies, or merely advises helps distinguish enforceable controls from prompt guidance.[^11][^12] |

The shared IDs and `related_l1_ids` / `related_l2_ids` make records traceable across technical endpoints, semantic operations, and agent-runtime behavior. Evidence fields show how strongly each claim is supported.


## Reusable justification

The schemas use linked records to describe the attack surface at the interface, business-operation, and agent-runtime levels. This captures not only where an attacker can supply or receive data, but also how values move across components, what permissions and state govern actions, where information persists, what effects operations produce, and which controls enforce policy. That structure follows established attack-surface and threat-modeling practice while making agent-specific risks—such as indirect prompt injection, excessive agency, memory exposure, and tool misuse—visible for review.

## Sources

[^1]: OWASP, [Attack Surface Analysis Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html).
[^2]: OWASP, [Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html).
[^3]: OWASP API Security Project, [API1:2023 Broken Object Level Authorization](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/).
[^4]: OWASP, [Business Logic Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html).
[^5]: OWASP Gen AI Security Project, [LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).
[^6]: OWASP Gen AI Security Project, [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/).
[^7]: OWASP Gen AI Security Project, [LLM07:2025 System Prompt Leakage](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/).
[^8]: Model Context Protocol, [Server Features Overview](https://modelcontextprotocol.io/specification/draft/server/index).
[^9]: Model Context Protocol, [Tool Annotations as Risk Vocabulary: What Hints Can and Can't Do](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/).
[^10]: OWASP Gen AI Security Project, [LLM08:2025 Vector and Embedding Weaknesses](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/).
[^11]: OWASP Gen AI Security Project, [LLM05:2025 Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/).
[^12]: OWASP Gen AI Security Project, [LLM10:2025 Unbounded Consumption](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/).
