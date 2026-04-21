# OSCP-NXC-PREY

A modular Bash wrapper for **authorized** Active Directory lab assessment and credential-validation workflows built around NetExec-style enumeration.

> Use only on systems and networks you are explicitly authorized to assess.

---

## Overview

`OSCP-NXC-PREY` is a structured, multi-phase Bash toolkit that coordinates common AD-focused enumeration tasks into a single workflow.

The project is organized around a main launcher, `nxc_spray.sh`, with separate modules for:

- argument parsing
- initialization and output handling
- credential parsing
- username preparation
- SMB, SSH, LDAP, Kerberos, and AD CS workflows
- optional extras and summaries

It is designed to reduce repetitive setup in OSCP-style or internal lab environments by keeping results, phases, and helper logic organized in one place.

---

## What it does

At a high level, the tool:

- prepares and validates runtime state
- creates and manages an output directory
- supports resume-style operation
- consolidates usernames and credential inputs
- performs domain-aware workflow setup
- can auto-detect AD domain context from reachable SMB targets
- can generate host mappings for better name resolution
- organizes execution into numbered phases with summaries

The code structure suggests a workflow focused on **environment prep, account validation, service-aware enumeration, and follow-up checks** rather than a single one-off command.

---

## Architecture

The repository is split into a main sequencer plus modules:

- `nxc_spray.sh` — main entrypoint / sequencer
- `modules/args.sh` — CLI parsing
- `modules/init.sh` — startup, validation, files, state
- `modules/creds.sh` — credential parsing and extraction
- `modules/users.sh` — username preparation and processing
- `modules/spray.sh` — main spray/enumeration orchestration
- `modules/kerberos.sh` — Kerberos-related attack surface checks
- `modules/adcs.sh` — AD CS and post-validation checks
- `modules/smb.sh` — SMB enumeration
- `modules/ssh.sh` — SSH enumeration
- `modules/ldap.sh` — LDAP highlighting and output handling
- `modules/ports.sh` — port/protocol target preparation
- `modules/extras.sh` — optional advanced checks
- `modules/summary.sh` — final reporting
- `modules/help.sh` — help/cheatsheet output
- `modules/utils.sh` — colors, runners, queue helpers, common utilities

This modular split makes the project easier to extend and maintain compared with a single large shell script.

---

## Key workflow features

### 1. Multi-phase execution
The script is structured into explicit phases, including:

- username preparation
- user validation logic
- domain/environment detection
- service-aware follow-up enumeration
- final summary generation

### 2. Domain-aware setup
The main flow attempts to identify:

- the AD domain
- a likely domain controller
- supporting hostnames for local resolution

It also includes time-sync logic intended to reduce Kerberos-related clock skew issues in lab environments.

### 3. Output organization
The wrapper prepares an output directory and stores intermediate files such as:

- generated usernames
- validated usernames
- service-specific results
- summary artifacts

### 4. Resume-friendly operation
The startup flow references resume state and boot initialization, suggesting it is designed to continue or reuse prior scan context rather than forcing a full rerun every time.

### 5. Tool orchestration
Rather than implementing everything itself, the script appears to act as a coordinator around existing tools and service-specific modules.

---

## Intended use case

This project looks best suited for:

- AD lab environments
- exam practice labs
- internal red/blue team validation labs
- structured enumeration where repeatability matters
- operators who want a single wrapper around repeated environment-prep steps

It is especially useful when you want:

- one command to kick off a staged workflow
- consistent output folders
- reusable username/credential preparation
- service-specific module separation

---

## Design style

The code is opinionated in a few useful ways:

- **modular shell design** instead of one monolithic script
- **phase-driven execution** for readability
- **environment auto-detection** where possible
- **helper output and summaries** to make results easier to review
- **shared utility module** for colors, command execution, and queue behavior

That makes it practical for iterative lab work and easier to customize for a personal workflow.

---

## Notable behaviors visible from the code

- early sudo caching so later commands do not prompt mid-run
- boot/init handling before the main phase execution
- optional username generation from a supplied user list
- optional user validation path before authenticated phases
- auto-detection of domain context from SMB results
- optional host-file generation behavior
- early clock sync handling for Kerberos-sensitive operations
- extras-only and generate-only execution modes

---

## Best fit

Use this project if you want a **single orchestrator** for:

- preparing AD-oriented enumeration runs
- organizing usernames and credentials
- standardizing service-aware follow-up checks
- keeping results and summaries in one place

---

## Safety

This project should only be used in:

- authorized lab environments
- approved internal assessments
- controlled training ranges
- systems where you have explicit written permission

Do not use it on third-party or production systems without authorization.
