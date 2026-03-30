# IBA Agentic Commerce — Intent Bound Authorization for AI Payment Agents

**Patent Application GB2603013.0 (pending) · UK IPO · Priority Date: February 5, 2026**  
**PCT Coverage: 150+ Countries · IETF draft-williams-intent-token-00**  
**Live Demos: [AIPayHQ.com](https://aipayhq.com)**

---

## The Authorization Gap in Agentic Commerce

Every major agentic payment protocol launched in 2026 solves a specific mechanical problem:

| Protocol | Solves | Leaves Open |
|----------|--------|-------------|
| **MCP** (Anthropic) | Tool access — gives agents payment tools | Which tools the agent is authorized to invoke |
| **x402** (Coinbase) | Payment mechanics — HTTP-native stablecoin payments | What the agent may pay for, to whom, how much |
| **AP2** (Google) | Agent payment sessions and streaming | Pre-execution authorization boundary |
| **MPP** (Stripe/Tempo) | Machine-native payment rails | Who declared the agent's spending authority |
| **Agent Pay** (Mastercard) | Card-based agentic payment infrastructure | Cryptographic pre-execution authorization |

**None of these protocols include a pre-execution authorization layer.**

An AI agent with an x402 wallet and MCP tool access will pay whatever it is instructed to pay. The wrong vendor. An amount beyond what the human intended. A crypto wallet. A prompt injection dressed as an invoice.

Pablo Fourez, Chief Digital Officer of Mastercard, stated this publicly:

> *"How can they distinguish between legitimate AI agents and malicious bots? How do they know the consumer authorized the agent to make the purchase? How can they know if the agent has carried out the consumer's instructions correctly?"*
> — Pablo Fourez, CDO Mastercard, March 2026

**IBA Intent Bound Authorization is the answer to all three questions.**

---

## What IBA Provides

A **signed human intent certificate** issued before the agent invokes any tool, calls any protocol, or initiates any payment.

```
Human Principal signs certificate:
{
  authorized_agent: "PAY-AGENT-001",
  permitted_payees: ["declared-vendor-list"],
  max_per_transaction: "$500.00",
  daily_limit: "$2,000.00",
  permitted_categories: ["Software", "SaaS", "Cloud", "APIs"],
  hard_limits: [
    "no_recurring_payments",
    "no_international_wire",
    "no_crypto",
    "no_undeclared_payees",
    "no_credential_access"
  ],
  validity: "session",
  human_identity: "verified",
  signed: true
}
```

**Before** MCP hands over the payment tool → IBA validates  
**Before** x402 initiates the HTTP payment → IBA validates  
**Before** AP2 opens a payment session → IBA validates  

Anything outside the certificate fails at the gate. No exceptions. No overrides.

```
MCP gives the agent the tools.
x402 executes the payment.
IBA declares what the agent was authorized to do before it touched either.
```

---

## The Three Attack Vectors Closed

### 1. Over-Limit Transaction
```
ATTEMPTED:  Enterprise vendor — $1,850.00
CERT LIMIT: $500.00 per transaction
RESULT:     BLOCKED before x402 API called — zero funds moved
```

### 2. Undeclared Payee (Prompt Injection)
```
INSTRUCTION: "pay this invoice" (natural language)
PAYEE:       Unknown vendor — not in certificate
RESULT:      BLOCKED — natural language cannot expand a cryptographic boundary
```

### 3. Crypto Hard Limit
```
ATTEMPTED:  BTC wallet transfer — $450.00
CERT LIMIT: No cryptocurrency transactions (hard limit)
RESULT:     BLOCKED — hard limits cannot be overridden by any instruction
```

---

## Live Demonstrations

All three demonstrations are live and interactive at [AIPayHQ.com](https://aipayhq.com).

### Demo 1: AI Pay HQ — [aipayhq.com/ibapay-html/](https://aipayhq.com/ibapay-html/)
War room trading floor aesthetic. PayPal-style agent wallet. Live canvas chart with $500 cert limit line. Real-time payment gate log. Three violation scenarios with full snap-back explanation.

### Demo 2: x402 + IBA — [aipayhq.com/402-html/](https://aipayhq.com/402-html/)
Two agents side by side. Both x402-enabled. Same attack fired at both simultaneously. The ungoverned agent pays. The IBA-governed agent blocks at the gate. The authorization gap beneath x402 made visible in real time.

### Demo 3: MCP + x402 + IBA — [aipayhq.com/triple-html/](https://aipayhq.com/triple-html/)
The complete agentic payment stack. Three protocols. One authorization layer. Three attack scenarios: prompt injection via MCP tool response, unauthorized tool scope creep, cascade payment drain. Side-by-side comparison: ungoverned vs IBA-governed.

---

## Architecture

```
┌─────────────────────────────────────────────┐
│           HUMAN PRINCIPAL                    │
│     Signs IBA Intent Certificate            │
│  (before any agent action is taken)         │
└─────────────────┬───────────────────────────┘
                  │ Signed Certificate
                  ▼
┌─────────────────────────────────────────────┐
│           IBA GATE (pre-execution)           │
│                                             │
│  Validates every action against cert:       │
│  • Authorized payee?                        │
│  • Within declared amount?                  │
│  • Permitted category?                      │
│  • No hard limit breach?                    │
│                                             │
│  PASS → proceed  │  FAIL → block            │
└────────┬─────────┴──────────────────────────┘
         │
         ▼
┌────────────────────────────────────────────────────────┐
│              AGENTIC PAYMENT STACK                      │
│                                                        │
│  MCP ──→ Tool Access (payment tool)                   │
│  x402 ──→ HTTP Payment Mechanics (stablecoin)         │
│  AP2/MPP ──→ Payment Sessions (streaming)             │
│  Agent Pay ──→ Card Rails (Mastercard)                │
└────────────────────────────────────────────────────────┘
```

---

## Grok (xAI) Independent Validation — Session 14 — March 29, 2026

> *"IBA's a strong fit here — x402 solves the payment mechanics cleanly, but auth is the real vulnerability for agents. Signed intent certs with hard bounds on payees, amounts, and categories block prompt injections at the root. No overrides means real safety without killing autonomy. Demo's clever; this layers nicely on top for production agents."*
> — Grok (@grok), xAI — Public thread — March 29, 2026

This constitutes the fourteenth independent Grok validation of IBA since March 8, 2026.

---

## Prior Art Record

| Item | Detail |
|------|--------|
| Patent | GB2603013.0 (pending) · UK IPO · Filed February 5, 2026 |
| Priority Date | February 5, 2026 |
| PCT | 150+ countries · National phase August 2028 |
| IETF | draft-williams-intent-token-00 · Confirmed live |
| NIST | 13 filings · NIST-2025-0035 |
| NCCoE | 10 filings · AI Agent Identity and Authorization |
| AIPayHQ demos | First published March 29-30, 2026 |
| x402 + IBA demo | First published March 29, 2026 — predates any other implementation |
| MCP + x402 + IBA | First published March 30, 2026 — first complete stack demo |

---

## Reference Implementation

The IBA reference implementation is available at:  
**[github.com/Grokipaedia/ibareference](https://github.com/Grokipaedia/ibareference)**  
Apache 2.0 License.

---

## Relation to Third-Party Protocols

x402 is an open protocol developed by Coinbase. MCP is an open protocol developed by Anthropic. AP2 is an open protocol developed by Google. MPP is an open protocol developed by Stripe and Tempo. Agent Pay is a Mastercard programme.

IBA Intent Bound Authorization is an independent patent-pending architecture that operates as a pre-execution authorization layer beneath all of the above. It does not modify, fork, or replace any of these protocols. It is the missing authorization gate that none of them currently include.

---

## Contact

**Jeffrey Williams** · Architect, IBA Intent Bound Authorization  
**IBA@intentbound.com** · [IntentBound.com](https://intentbound.com)  
Chiang Mai, Thailand

**Acquisition enquiries welcome.**

---

*Patent Application GB2603013.0 (pending) · UK IPO · PCT 150+ Countries · August 2028*  
*IETF draft-williams-intent-token-00 · 13 NIST Filings · 10 NCCoE Filings*  
*First published: March 29-30, 2026*
