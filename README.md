# eBPF-problem-set-answers

**Status:** ✅ Completed

**Author:** Ved Walvekar
**Date:** 2025-10-28

---

## Overview

This repository contains my completed solutions for the **eBPF problem set**, covering a range of eBPF applications across networking, tracing, and system monitoring. Each solution focuses on demonstrating practical eBPF concepts with clear and minimal code.

## Problem Approaches

### Problem 1 — Packet Filtering (XDP)

This eBPF program filters incoming TCP packets by checking their destination ports. It parses Ethernet, IP, and TCP headers safely, then looks up the destination port in a BPF hash map (`block_list`). If the port is blocked, it logs the event through a perf buffer and drops the packet; otherwise, it lets it pass. This enables efficient, dynamic port-based packet blocking at the kernel level.

**Concepts used:** Traffic Control (TC) hooks, Kernel-level filtering.

Resources used: eBPF documentation, bcc documentation, eBPF guide repos.

---

### Problem 2 — Socket-level Filtering

This eBPF program monitors outgoing TCP packets and blocks traffic from a specific process if it’s not using an allowed port. It attaches to the egress hook, safely parses Ethernet, IP, and TCP headers, and retrieves the current process name. If the process name matches the target (`myprocess`) but its source port differs from the allowed one (4040), the packet details are sent to user space via a perf buffer, and the packet is dropped. This enables process-aware, port-based egress filtering directly in the kernel.

**Concepts used:** Traffic Control (TC) hooks, Kernel-level filtering.

Resources used: eBPF documentation, bcc documentation, eBPF guide repos.

---

### Problem 3 — Channels and Goroutines

Explained the given Go program in detail.

**Resources used:** Way to Go(book), Go documentation.
