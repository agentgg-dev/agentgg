import type { Agent } from "@agentgg/core";

/**
 * The bar a live claim must clear. It is stated once, for every class,
 * because the shape of proof does not vary with the vulnerability: an
 * effect the application must not allow, attributable to the attacker's
 * input, and absent without it.
 */
export const PROOF_PRINCIPLE = `- You caused an effect the application must not allow. A page that
  responded, or text that came back, is not an effect.
- The effect is attributable to YOUR input. Name the input that carried it.
- Run the same steps without your input, or without the session, and show
  that the effect does not happen.
- If you cannot isolate the effect to your own input, the result is
  'inconclusive'. Never report an effect your own setup produced as proof.`;

/**
 * The reporting agent may add to the bar, never lower it, so its rule is
 * appended to the principle rather than replacing it.
 */
export function proofRules(agentRule?: string): string {
  const extra = agentRule?.trim();
  return extra
    ? `${PROOF_PRINCIPLE}\n\nFor this class, additionally:\n\n${extra}`
    : PROOF_PRINCIPLE;
}

/** Agents whose class reports a missing control rather than an effect an
 *  attacker can cause. Absent means testable, so opting out is deliberate. */
export function notLiveReproducible(agents: readonly Agent[]): Set<string> {
  const out = new Set<string>();
  for (const a of agents) if (a.liveReproducible === false) out.add(a.slug);
  return out;
}

/** The agents that declare a rule, keyed by slug. An agent that declares none
 *  is absent, and its findings run on the principle alone. */
export function proofRuleMap(agents: readonly Agent[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const a of agents) if (a.liveProofRule) map.set(a.slug, a.liveProofRule);
  return map;
}
