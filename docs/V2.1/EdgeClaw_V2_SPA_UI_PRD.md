# EdgeClaw V2.1 SPA UI PRD

Version: 2.1  
Date: 2026-03-15  
Scope: SPA integration + Extensions menu

---

## 1. Objectives
- Preserve existing menus and features.
- Ensure a single SPA shell with view switching.
- Add an Extensions menu for modular automation.

---

## 2. Information Architecture
- Mission Control
- Agents
- Memory
- Automations
- Marketplace
- Settings
- Extensions (new)

---

## 3. SPA Routing & View Model
- Single HTML shell with `view-*` sections.
- Hash routing: `#dashboard`, `#agents`, `#memory`, `#automations`, `#market`, `#settings`, `#extensions`.
- Deep-link format for Extensions: `#extensions:notes` etc.

---

## 4. Extensions Menu PRD

### 4.1 Modules
- Notes, Compute, Security, Network, Economy

### 4.2 Core UX
- Module list, search, filter, and status badges.
- Execution readiness panel (policy, connectors, queue health).
- One-click onboarding for new modules.

### 4.3 Integration
- Outputs connect to Mission Control, Memory, Automations.
- RBAC policy approval required for privileged modules.

---

## 5. DoD
- All menus switch within a single SPA.
- Extensions view loads without page change.
- Hash-based deep links restore state after refresh.

