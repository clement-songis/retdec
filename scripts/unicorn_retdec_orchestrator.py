#!/usr/bin/env python3
"""Portable, fail-closed Unicorn evidence -> RetDec plan orchestrator.

This file deliberately uses only the Python standard library.  It neither runs
Unicorn/RetDec nor changes an image.  Copy it as
``scripts/unicorn_retdec_orchestrator.py`` in the RetDec fork, or import it as a
module.  All input artifacts are supplied by the caller; no vgk sample, project
checkout, absolute path, Capstone, pefile, or Unicorn installation is required
by the self-test.

Commands (relative paths are resolved against --workspace, default: cwd)::

  python3 unicorn_retdec_orchestrator.py request --site-rva 0x100 \
    --proof-type control-flow-target --image image.bin --image-sha256 SHA \
    --output request.json
  python3 unicorn_retdec_orchestrator.py validate --request request.json \
    --response evidence.json --response-sha256 SHA --witness-sha256 SHA \
    --overlay-output overlay.json --output result.json
  python3 unicorn_retdec_orchestrator.py self-test --output selftest.json

The response SHA256 covers the exact file bytes.  The witness SHA256 covers the
canonical ``unicornretdec-witness-set-v1`` object, sorted by observationId.
These hashes provide integrity and joins, not authentication or signatures.
Every rejected/incomplete input returns status=unknown, no eligible evidence,
and no RetDec plan.  An explicitly requested overlay is all-or-nothing for the
request site and targets: missing, conflicting, zero-fill, or unknown-page
captures reject the request instead of producing a partial overlay.
"""
from __future__ import annotations

import argparse
import collections
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REQUEST_FORMAT = "unicornretdec-request-v1"
RESULT_FORMAT = "unicornretdec-result-v1"
PLAN_FORMAT = "unicornretdec-retdec-plan-v1"
WITNESS_FORMAT = "unicornretdec-witness-set-v1"
MANIFEST_FORMAT = "unicornretdec-proof-manifest-v1"
EVIDENCE_FORMAT = "retdec-griffin-evidence-v2"
OVERLAY_FORMAT = "griffin-analysis-overlay-v1"
PROOF_TYPES = ("control-flow-target", "control-flow-target-set", "stack-role")
ROLES = ("abi-frame", "vm-register", "vm-spill", "any-proved")
STACK_SLOT_ROLES = {"unknown", "abi-frame", "vm-register", "vm-spill"}
CLASSES = {"static", "dynamic-verified", "dynamic-scratch", "ambiguous"}
SHA256_HEX = frozenset("0123456789abcdef")
MASK64 = (1 << 64) - 1
PAGE = 0x1000
MAX_WITNESSES = 256
MAX_TARGETS = 256
MAX_OVERLAY_BYTES = 1024 * 1024
MAX_RETDEC_SPAN = 16 * 1024 * 1024
STACK_OPERAND = re.compile(
    r"^(call|jmp) qword ptr \[rsp(?: ([+-]) (0x[0-9a-fA-F]+|[0-9]+))?\]$")
ROLE_FOR_KIND = {
    "abi-frame-lifetime": "abi-frame",
    "vm-register-dataflow": "vm-register",
    "vm-spill-dataflow": "vm-spill",
}
TARGET_PROOF_KINDS = {
    "exhaustive-state-enumeration",
    "complete-jump-table",
    "complete-static-cff",
}
REAL_CAPTURE_CLASSES = {"live", "emulated-real-input", "runtime-dump"}
OBSERVATION_ID_KEYS = (
    "run", "seed", "wave", "step", "sourceVa", "targetVa", "sourceRva",
    "targetRva", "mnemonic", "contextSha256", "imageSha256",
)
CAPTURE_ID_KEYS = (
    "run", "seed", "wave", "step", "va", "rva", "instructionBytes",
    "contextSha256", "imageSha256",
)


class ProofRejected(ValueError):
    """A machine-reportable fail-closed rejection."""

    def __init__(self, *reasons, diagnostics=None):
        super().__init__(", ".join(str(r) for r in reasons))
        self.reasons = sorted(set(str(r) for r in reasons))
        self.diagnostics = diagnostics


def parse_int(value):
    if isinstance(value, bool) or value is None:
        raise ValueError("integer address required")
    return value if isinstance(value, int) else int(value, 0)


def jint(value):
    return None if value is None else hex(int(value))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def json_text(value):
    return json.dumps(value, indent=1, ensure_ascii=False) + "\n"


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def is_sha256(value):
    return (isinstance(value, str) and len(value) == 64
            and bool(set(value) <= SHA256_HEX))


def context_hash(context):
    material = {key: context.get(key)
                for key in ("capture", "complete", "registers", "memory")}
    return sha256_bytes(canonical(material).encode())


def observation_id(observation):
    return sha256_bytes(canonical(
        {key: observation.get(key) for key in OBSERVATION_ID_KEYS}).encode())


def instruction_capture_id(capture):
    return sha256_bytes(canonical(
        {key: capture.get(key) for key in CAPTURE_ID_KEYS}).encode())


def proof_hash(proof):
    return sha256_bytes(canonical(
        {key: value for key, value in proof.items() if key != "proofSha256"}).encode())


def witness_set_sha256(witnesses):
    ordered = sorted(witnesses, key=lambda item: item.get("observationId") or "")
    return sha256_bytes(canonical(
        {"format": WITNESS_FORMAT, "witnesses": ordered}).encode())


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json_text(payload), encoding="utf-8")
    os.replace(temporary, path)
    return sha256_file(path)


def path_reference(path, workspace):
    """Keep artifacts relocatable whenever the caller path is in workspace."""
    path = Path(path)
    workspace = Path(workspace).resolve()
    if path.is_absolute():
        try:
            return path.resolve().relative_to(workspace).as_posix()
        except ValueError:
            return str(path)
    return Path(os.path.normpath(str(path))).as_posix()


def resolve_path(reference, workspace):
    reference = Path(reference)
    return reference if reference.is_absolute() else Path(workspace) / reference


def _bad_provenance(value):
    text = str(value or "").lower()
    markers = ("zero-fill", "zero_filled", "zero-filled", "unknown-page",
               "unknown_page", "uninitialized", "scratch-zero", "image-zero",
               "unknown-zero")
    return any(marker in text for marker in markers)


def no_zero_fill_reasons(observation, capture=None):
    reasons = []
    context = observation.get("context") or {}
    if context.get("complete") is not True:
        reasons.append("witness-context-incomplete")
    taint = observation.get("scratch-taint") or {}
    if taint.get("tainted") or taint.get("unknown"):
        reasons.append("witness-scratch-tainted-or-unknown-page")
    if taint.get("reads"):
        reasons.append("witness-scratch-reads-present")
    replay = observation.get("replay") or {}
    if replay.get("missing"):
        reasons.append("witness-replay-missing-pages")
    if replay.get("error") is not None:
        reasons.append("witness-replay-error")
    for item in context.get("memory") or []:
        if _bad_provenance(item.get("provenance")):
            reasons.append("witness-memory-zero-fill-or-unknown-provenance")
    if capture is not None:
        capture_taint = capture.get("scratch-taint") or {}
        if (capture_taint.get("tainted") or capture_taint.get("unknown")
                or capture_taint.get("reads")):
            reasons.append("instruction-capture-scratch-or-unknown-page")
        provenance = capture.get("provenance") or {}
        if (provenance.get("timing") != "before-execution"
                or provenance.get("bytesReadFrom") != "emulated-memory"):
            reasons.append("instruction-capture-byte-provenance-invalid")
        if _bad_provenance(provenance.get("codePageOrigin")):
            reasons.append("instruction-page-zero-fill-or-unknown-provenance")
        for item in (capture.get("context") or {}).get("memory") or []:
            if _bad_provenance(item.get("provenance")):
                reasons.append("instruction-memory-zero-fill-or-unknown-provenance")
    return sorted(set(reasons))


def classify_observation(observation):
    target = observation.get("targetRva")
    static = observation.get("staticTargetRva")
    taint = observation.get("scratch-taint") or {}
    if static is not None:
        return "static" if target == static else "ambiguous"
    if taint.get("tainted"):
        return "dynamic-scratch"
    if (taint.get("unknown") or target is None
            or not (observation.get("context") or {}).get("complete")):
        return "ambiguous"
    replay = observation.get("replay") or {}
    return ("dynamic-verified"
            if replay.get("status") == "match"
            and replay.get("actualTargetRva") == target else "ambiguous")


def clean_dynamic(observation, target=None):
    return (observation.get("classification") == "dynamic-verified"
            and classify_observation(observation) == "dynamic-verified"
            and observation.get("targetRva") is not None
            and (target is None or observation.get("targetRva") == target)
            and (observation.get("context") or {}).get("complete") is True
            and (observation.get("replay") or {}).get("status") == "match"
            and (observation.get("replay") or {}).get("actualTargetRva")
                == observation.get("targetRva")
            and not (observation.get("scratch-taint") or {}).get("tainted")
            and not (observation.get("scratch-taint") or {}).get("unknown"))


def _negative_control(evidence):
    control = evidence.get("negativeControl") or {}
    return (control.get("status") == "pass" and bool(control.get("kind"))
            and bool(control.get("observationId") or control.get("captureId")))


def _instruction_sha256(observation, captures_by_id):
    values = []
    if observation.get("instructionSha256"):
        values.append(observation["instructionSha256"])
    capture = captures_by_id.get(observation.get("instructionCaptureId"))
    if capture and capture.get("instructionSha256"):
        values.append(capture["instructionSha256"])
    if observation.get("instructionBytes"):
        try:
            values.append(sha256_bytes(bytes.fromhex(observation["instructionBytes"])))
        except ValueError:
            values.append("invalid-hex")
    return values[0] if values and len(set(values)) == 1 else None


def validate_role_proof(observation, captures_by_id, image_sha256):
    prior = observation.get("stackSlot") or {}
    proof = observation.get("stackRoleProof") or prior.get("roleProof")
    role = prior.get("role") or observation.get("stackRole") or "unknown"
    if not proof:
        return {"status": "missing", "role": "unknown",
                "reasons": ["explicit-role-proof-missing"]}
    if not isinstance(proof, dict):
        return {"status": "rejected", "role": "unknown",
                "reasons": ["role-proof-not-an-object"]}
    reasons = []
    expected_role = ROLE_FOR_KIND.get(proof.get("kind"))
    if expected_role is None:
        reasons.append("unsupported-or-synthetic-role-proof-kind")
    else:
        role = expected_role
    if proof.get("status") != "proved":
        reasons.append("role-proof-status-not-proved")
    if proof.get("role") != role or role not in STACK_SLOT_ROLES - {"unknown"}:
        reasons.append("role-proof-role-mismatch")
    if prior.get("roleProven") is not True and observation.get("stackRoleProof") is None:
        reasons.append("roleProven-not-true")
    bindings = {
        "imageSha256": image_sha256,
        "sourceRva": observation.get("sourceRva"),
        "observationId": observation.get("observationId"),
        "contextSha256": observation.get("contextSha256"),
        "instructionSha256": _instruction_sha256(observation, captures_by_id),
        "displacement": prior.get("displacement"),
    }
    for key, expected in bindings.items():
        if expected is None or proof.get(key) != expected:
            reasons.append(f"role-proof-{key}-mismatch")
    evidence = proof.get("evidence")
    if not isinstance(evidence, dict):
        reasons.append("role-proof-evidence-missing")
        evidence = {}
    if evidence.get("captureClass") not in REAL_CAPTURE_CLASSES:
        reasons.append("role-proof-not-real-capture")
    writer = evidence.get("writerCapture") or {}
    if (not writer.get("captureId") or not writer.get("contextSha256")
            or not writer.get("postContextSha256")):
        reasons.append("role-writer-capture-incomplete")
    if writer.get("address") != prior.get("address") or writer.get("size") != 8:
        reasons.append("role-writer-slot-mismatch")
    replay = writer.get("replay") or {}
    if (replay.get("status") != "match"
            or (replay.get("postContext") or {}).get("status") != "match"):
        reasons.append("role-writer-replay-not-clean")
    activation = evidence.get("activation") or {}
    if (not activation.get("activationId") or not activation.get("entryCaptureId")
            or not activation.get("exitCaptureId")):
        reasons.append("role-activation-lifetime-incomplete")
    if role == "abi-frame":
        frame = evidence.get("nativeFrame") or {}
        if not frame.get("entryRsp") or not frame.get("frameLo") or not frame.get("frameHi"):
            reasons.append("abi-frame-bounds-missing")
        try:
            contains = (parse_int(frame["frameLo"]) <= parse_int(prior["address"])
                        < parse_int(frame["frameHi"]))
        except (KeyError, TypeError, ValueError):
            contains = False
        if not contains or frame.get("containsSlot") is not True:
            reasons.append("abi-frame-slot-outside-proved-lifetime")
        if frame.get("lifetimeComplete") is not True or frame.get("rspDeltasMatch") is not True:
            reasons.append("abi-frame-rsp-lifetime-not-proved")
    elif role == "vm-register":
        vm = evidence.get("vmContext") or {}
        if (not vm.get("contextId") or not vm.get("slotId")
                or not vm.get("contextLineageProof")
                or len(vm.get("handlerUseCaptureIds") or []) < 2):
            reasons.append("vm-register-context-or-multi-handler-use-missing")
    elif role == "vm-spill":
        vm = evidence.get("vmSpill") or {}
        if (not vm.get("contextId") or not vm.get("slotId")
                or not vm.get("reloadCaptureId")
                or vm.get("defUseChainComplete") is not True):
            reasons.append("vm-spill-def-use-chain-incomplete")
    if not _negative_control(evidence):
        reasons.append("role-negative-control-missing")
    if proof.get("proofSha256") != proof_hash(proof):
        reasons.append("role-proof-hash-mismatch")
    return {"status": "proved" if not reasons else "rejected",
            "role": role if not reasons else "unknown",
            "proofSha256": proof.get("proofSha256"),
            "reasons": sorted(set(reasons))}


def validate_target_set_proof(site, observations, image_sha256):
    proof = site.get("targetSetProof")
    reasons = []
    if site.get("kind") != "jmp":
        reasons.append("provider-cff-requires-jmp-not-ret-or-call")
    targets = sorted(site.get("targets") or [], key=parse_int)
    if len(targets) <= 1:
        reasons.append("provider-cff-requires-multiple-targets")
    if not proof:
        reasons.append("explicit-target-set-proof-missing")
        proof = {}
    if proof.get("status") == "missing":
        reasons.append("explicit-target-set-proof-missing")
    if proof.get("status") != "proved":
        reasons.append("target-set-proof-status-not-proved")
    if proof.get("kind") not in TARGET_PROOF_KINDS:
        reasons.append("unsupported-or-synthetic-target-set-proof-kind")
    if proof.get("imageSha256") != image_sha256 or proof.get("siteRva") != site.get("siteRva"):
        reasons.append("target-set-image-or-site-mismatch")
    if proof.get("targets") != targets:
        reasons.append("target-set-target-list-mismatch")
    expected_ids = sorted(item.get("observationId") for item in observations)
    if sorted(proof.get("observationIds") or []) != expected_ids:
        reasons.append("target-set-observation-coverage-mismatch")
    evidence = proof.get("evidence")
    if not isinstance(evidence, dict):
        reasons.append("target-set-evidence-missing")
        evidence = {}
    if evidence.get("captureClass") not in REAL_CAPTURE_CLASSES:
        reasons.append("target-set-not-real-capture")
    domain = evidence.get("domain") or {}
    entries = domain.get("entries") or []
    if (domain.get("kind") not in {"finite-state", "jump-table"}
            or domain.get("complete") is not True):
        reasons.append("target-set-domain-not-explicitly-complete")
    if not entries or domain.get("entryCount") != len(entries):
        reasons.append("target-set-domain-entry-count-mismatch")
    entry_targets, states = set(), set()
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("targetRva") not in targets:
            reasons.append("target-set-domain-entry-invalid")
            continue
        entry_targets.add(entry["targetRva"])
        if domain.get("kind") == "finite-state":
            try:
                state = parse_int(entry["stateValue"])
            except (KeyError, TypeError, ValueError):
                reasons.append("target-set-state-missing")
                continue
            if state in states:
                reasons.append("target-set-duplicate-state")
            states.add(state)
    if entry_targets != set(targets):
        reasons.append("target-set-domain-does-not-cover-all-targets")
    if domain.get("kind") == "jump-table":
        table = evidence.get("table") or {}
        if (not table.get("baseRva") or not table.get("entrySize")
                or not table.get("boundsProof") or not table.get("entriesDigest")):
            reasons.append("target-set-jump-table-bounds-or-bytes-missing")
    if not _negative_control(evidence):
        reasons.append("target-set-negative-control-missing")
    if proof.get("proofSha256") != proof_hash(proof):
        reasons.append("target-set-proof-hash-mismatch")
    by_target = {target: [item for item in observations if clean_dynamic(item, target)]
                 for target in targets}
    if any(not matches for matches in by_target.values()):
        reasons.append("target-set-clean-replay-missing-for-a-target")
    if len(observations) != sum(len(matches) for matches in by_target.values()):
        reasons.append("target-set-contains-unclean-or-external-observation")
    cases = site.get("targetCases")
    if site.get("stateOperand") or cases is not None:
        if site.get("stateOperand") != "pseudo-arg" or domain.get("kind") != "finite-state":
            reasons.append("target-set-state-operand-or-domain-mismatch")
        elif not isinstance(cases, list) or len(cases) != len(targets):
            reasons.append("target-set-cases-not-one-per-target")
        else:
            seen_targets, seen_states = set(), set()
            for case in cases:
                target = case.get("targetRva")
                try:
                    state = parse_int(case.get("stateValue"))
                except (TypeError, ValueError):
                    reasons.append("target-set-case-state-invalid")
                    continue
                matched = any(
                    parse_int(item.get("stateValue")) == state
                    for item in by_target.get(target, []) if item.get("stateValue") is not None)
                if target in seen_targets or state in seen_states or not matched:
                    reasons.append("target-set-case-not-matched-to-observation")
                seen_targets.add(target)
                seen_states.add(state)
            if seen_targets != set(targets) or seen_states != states:
                reasons.append("target-set-cases-do-not-cover-domain")
    return {"status": "proved" if not reasons else "rejected",
            "proofSha256": proof.get("proofSha256"),
            "reasons": sorted(set(reasons))}


def derive_stack_slot(observation):
    match = STACK_OPERAND.fullmatch(observation.get("text") or "")
    if not match or observation.get("mnemonic") != match.group(1):
        return None
    displacement = int(match.group(3), 0) if match.group(3) else 0
    if match.group(2) == "-":
        displacement = -displacement
    prior = observation.get("stackSlot") or {}
    reasons = []
    if (prior.get("displacement") is not None
            and parse_int(prior["displacement"]) != displacement):
        reasons.append("annotation-displacement-mismatch")
    context = observation.get("context") or {}
    rsp = observation.get("rsp")
    address, matching_memory = None, None
    if rsp is None or (context.get("registers") or {}).get("rsp") != rsp:
        reasons.append("rsp-missing-or-inconsistent")
    else:
        address = (parse_int(rsp) + displacement) & MASK64
        target_va = (parse_int(observation["targetVa"])
                     if observation.get("targetVa") is not None else None)
        for item in context.get("memory") or []:
            try:
                raw = bytes.fromhex(item.get("data") or "")
                if (parse_int(item["address"]) == address and item.get("size") == 8
                        and len(raw) == 8 and int.from_bytes(raw, "little") == target_va):
                    matching_memory = item
                    break
            except (KeyError, TypeError, ValueError):
                continue
        if matching_memory is None:
            reasons.append("captured-slot-value-does-not-match-target")
    clean = clean_dynamic(observation) and observation.get("targetVa") is not None
    if not clean:
        reasons.append("observation-not-dynamic-verified")
    if (context.get("sha256") != context_hash(context)
            or observation.get("contextSha256") != context.get("sha256")):
        reasons.append("context-hash-mismatch")
    role = prior.get("role", "unknown")
    role_proof = prior.get("roleProof") or {}
    role_proved = (role in STACK_SLOT_ROLES - {"unknown"}
                   and prior.get("roleProven") is True
                   and role_proof.get("status") == "proved")
    role_rejected = role not in STACK_SLOT_ROLES or (role != "unknown" and not role_proved)
    if not role_proved:
        role = "unknown"
    result = {
        "role": role, "roleProven": role_proved,
        "displacement": str(displacement) if displacement < 0 else hex(displacement),
        "address": jint(address), "size": 8,
        "providerEligible": clean and not reasons and matching_memory is not None,
        "imageSha256": observation.get("imageSha256"),
        "sourceRva": observation.get("sourceRva"),
        "targetRva": observation.get("targetRva"),
        "observationId": observation.get("observationId"),
        "contextSha256": observation.get("contextSha256"),
        "replay": {
            "status": (observation.get("replay") or {}).get("status"),
            "actualTargetRva": (observation.get("replay") or {}).get("actualTargetRva"),
        },
        "rejectReasons": sorted(set(reasons)),
        "providerRule": ("call/jmp [rsp+disp] + captured qword == targetVa + clean matching "
                         "replay; role explicite prouve ou unknown"),
    }
    if role_proved:
        result["roleProof"] = role_proof
    if role_rejected:
        result["roleRejected"] = True
        result["roleRejectReason"] = "explicit-role-proof-required"
    return result


def _static_direct_target(observation):
    """Decode only direct x86 branches; dynamic/indirect bytes never promote."""
    try:
        raw = bytes.fromhex(observation.get("instructionBytes") or "")
        source = parse_int(observation["sourceVa"])
        target = parse_int(observation["targetVa"])
        mnemonic = observation.get("mnemonic")
        displacement = None
        length = None
        if len(raw) >= 5 and raw[0] in (0xE8, 0xE9):
            length = 5
            displacement = int.from_bytes(raw[1:5], "little", signed=True)
        elif len(raw) >= 2 and raw[0] in (0xEB, *range(0x70, 0x80)):
            length = 2
            displacement = int.from_bytes(raw[1:2], "little", signed=True)
        elif len(raw) >= 6 and raw[0] == 0x0F and 0x80 <= raw[1] <= 0x8F:
            length = 6
            displacement = int.from_bytes(raw[2:6], "little", signed=True)
        if length is None or len(raw) != length:
            return False
        expected = (source + length + displacement) & MASK64
        return (target & MASK64) == expected and (
            (raw[0] == 0xE8 and mnemonic == "call")
            or (raw[0] in (0xE9, 0xEB) and mnemonic == "jmp")
            or mnemonic not in ("call", "jmp", "ret"))
    except (KeyError, TypeError, ValueError):
        return False


def audit_sidecar(response, image_sha256, image_path=None):
    """Dependency-free global audit; malformed input is never provider evidence.

    For RVA-layout images, passing image_path also checks every static proof's
    instruction bytes against the hashed image itself, replacing the PoC's
    Capstone dependency without trusting capture bytes blindly.
    """
    violations = []
    if response.get("format") != EVIDENCE_FORMAT:
        return {"status": "fail", "violations": ["format-non-v2"]}
    image = response.get("image") or {}
    if image.get("sha256") != image_sha256:
        violations.append("image-sha256-mismatch")
    if image.get("layout") != "rva":
        violations.append("provider-image-layout-not-rva")
    model = response.get("addressModel") or {}
    try:
        image_size = parse_int(model["imageSize"])
        if image_size <= 0 or model.get("key") != "RVA":
            raise ValueError("bad model")
        for key in ("staticImageBase", "runtimeImageBase"):
            parse_int(model[key])
    except (KeyError, TypeError, ValueError):
        return {"status": "fail", "violations": violations + ["invalid-address-model"]}

    captures = response.get("instructionCaptures") or []
    captures_by_id = {}
    capture_ids = set()
    for index, capture in enumerate(captures):
        cid = capture.get("captureId") or f"capture-index-{index}"
        if cid in capture_ids:
            violations.append(f"{cid}:duplicate-capture-id")
        capture_ids.add(cid)
        captures_by_id[cid] = capture
        try:
            raw = bytes.fromhex(capture.get("instructionBytes") or "")
            if not raw or len(raw) != capture.get("length"):
                violations.append(f"{cid}:instruction-length")
            if sha256_bytes(raw) != capture.get("instructionSha256"):
                violations.append(f"{cid}:instruction-sha256")
            if capture.get("rva") is None or not 0 <= parse_int(capture["rva"]) < image_size:
                violations.append(f"{cid}:capture-rva-outside-image")
            if parse_int(capture["rva"]) + len(raw) > image_size:
                violations.append(f"{cid}:capture-bytes-outside-image")
        except (KeyError, TypeError, ValueError):
            violations.append(f"{cid}:invalid-instruction-bytes-or-rva")
        if (not str(cid).startswith("legacy-")
                and capture.get("captureId") != instruction_capture_id(capture)):
            violations.append(f"{cid}:capture-id-hash")
        if capture.get("imageSha256") != image_sha256:
            violations.append(f"{cid}:capture-image-hash")
        context = capture.get("context") or {}
        if (context.get("sha256") != context_hash(context)
                or capture.get("contextSha256") != context.get("sha256")):
            violations.append(f"{cid}:capture-context-hash")
        provenance = capture.get("provenance") or {}
        if (provenance.get("timing") != "before-execution"
                or provenance.get("bytesReadFrom") != "emulated-memory"):
            violations.append(f"{cid}:capture-byte-provenance")
        # Scratch/zero provenance is scoped to selected witnesses and requested
        # overlay RVAs below.  An unrelated rejected capture must not poison an
        # otherwise independent proof in the same evidence-v2 sidecar.

    observations = response.get("observations") or []
    by_id = {}
    for index, observation in enumerate(observations):
        oid = observation.get("observationId") or f"index-{index}"
        if oid in by_id:
            violations.append(f"{oid}:duplicate-observation-id")
        by_id[oid] = observation
        required = ("sourceRva", "mnemonic", "rsp", "seed", "wave", "context",
                    "runtimeImageBase", "imageSha256", "scratch-taint",
                    "classification", "observationId")
        for key in required:
            if key not in observation:
                violations.append(f"{oid}:missing-{key}")
        if observation.get("observationId") != observation_id(observation):
            violations.append(f"{oid}:observation-id-hash")
        if observation.get("imageSha256") != image_sha256:
            violations.append(f"{oid}:observation-image-hash")
        context = observation.get("context") or {}
        if (context.get("sha256") != context_hash(context)
                or observation.get("contextSha256") != context.get("sha256")):
            violations.append(f"{oid}:context-hash")
        try:
            source = parse_int(observation["sourceRva"])
            if not 0 <= source < image_size:
                violations.append(f"{oid}:source-outside-image")
            target = observation.get("targetRva")
            if target is not None and not 0 <= parse_int(target) < image_size:
                violations.append(f"{oid}:target-outside-image")
        except (KeyError, TypeError, ValueError):
            violations.append(f"{oid}:invalid-address")
        classification = observation.get("classification")
        if classification not in CLASSES:
            violations.append(f"{oid}:bad-class")
        elif classification != classify_observation(observation):
            violations.append(f"{oid}:classification-not-derived-from-proof")
        if classification == "static":
            static_ok = (observation.get("staticTargetRva") == observation.get("targetRva")
                         and _static_direct_target(observation))
            if image_path is None:
                violations.append(f"{oid}:static-image-bytes-not-checked")
            else:
                try:
                    raw = bytes.fromhex(observation.get("instructionBytes") or "")
                    with Path(image_path).open("rb") as source_file:
                        source_file.seek(parse_int(observation["sourceRva"]))
                        image_raw = source_file.read(len(raw))
                    if not raw or image_raw != raw:
                        violations.append(f"{oid}:static-image-byte-mismatch")
                except (KeyError, OSError, TypeError, ValueError):
                    violations.append(f"{oid}:static-image-byte-read-failed")
            if not static_ok:
                violations.append(f"{oid}:static-not-confirmed-by-image-bytes")
        if classification == "dynamic-verified" and not clean_dynamic(observation):
            violations.append(f"{oid}:verified-without-clean-matching-replay")
        if (classification == "dynamic-scratch"
                and not (observation.get("scratch-taint") or {}).get("tainted")):
            violations.append(f"{oid}:scratch-class-without-taint")
        if captures and observation.get("instructionCaptureId") not in capture_ids:
            violations.append(f"{oid}:missing-source-instruction-capture")
        if observation.get("stackSlot") is not None:
            expected = derive_stack_slot(observation)
            if expected is None or canonical(expected) != canonical(observation["stackSlot"]):
                violations.append(f"{oid}:stack-slot-not-derived-from-proof")
            else:
                slot = observation["stackSlot"]
                if slot.get("providerEligible") and not clean_dynamic(observation):
                    violations.append(f"{oid}:stack-slot-eligible-without-verified-proof")
                if slot.get("role") != "unknown":
                    verdict = validate_role_proof(observation, captures_by_id, image_sha256)
                    if verdict["status"] != "proved" or verdict.get("role") != slot.get("role"):
                        violations.append(f"{oid}:stack-slot-role-proof-invalid")

    eligible_targets = set()
    eligible_count = 0
    seen_sites = set()
    for site in response.get("controlFlowSites") or []:
        sid = site.get("siteRva")
        if sid in seen_sites:
            violations.append(f"site-{sid}:duplicate-site")
        seen_sites.add(sid)
        ids = site.get("observationIds") or []
        if not ids or len(set(ids)) != len(ids):
            violations.append(f"site-{sid}:missing-or-duplicate-observation-ids")
        supporting = [by_id.get(oid) for oid in ids]
        if any(item is None for item in supporting):
            violations.append(f"site-{sid}:missing-observation")
            continue
        targets = site.get("targets") or []
        eligible = site.get("providerEligible") is True
        if len(targets) > MAX_TARGETS:
            violations.append(f"site-{sid}:target-limit-exceeded")
        try:
            if len(set(targets)) != len(targets):
                violations.append(f"site-{sid}:duplicate-targets")
            if eligible and not targets:
                violations.append(f"site-{sid}:eligible-without-targets")
            if any(not 0 < parse_int(target) < image_size for target in targets):
                violations.append(f"site-{sid}:target-zero-or-outside-image")
        except (TypeError, ValueError):
            violations.append(f"site-{sid}:invalid-target")
        if eligible:
            eligible_count += 1
            if site.get("classification") not in {"static", "dynamic-verified"}:
                violations.append(f"site-{sid}:bad-eligible-class")
            if any(item.get("classification") == "ambiguous" for item in supporting):
                violations.append(f"site-{sid}:eligible-with-ambiguous-observation")
            if len(targets) == 1:
                if site.get("targetRva") != targets[0]:
                    violations.append(f"site-{sid}:single-target-mismatch")
                good = [item for item in supporting
                        if item.get("classification") == site.get("classification")
                        and item.get("targetRva") == targets[0]
                        and (item.get("classification") == "static" or clean_dynamic(item))]
                if not good:
                    violations.append(f"site-{sid}:eligible-without-supporting-proof")
            else:
                verdict = validate_target_set_proof(site, supporting, image_sha256)
                if site.get("targetSetComplete") is not True:
                    violations.append(f"site-{sid}:targetSetComplete-not-true")
                violations.extend(f"site-{sid}:{reason}" for reason in verdict["reasons"])
            eligible_targets.update(targets)
        elif len(targets) > 1 and site.get("targetSetComplete") is True:
            verdict = validate_target_set_proof(site, supporting, image_sha256)
            violations.extend(f"site-{sid}:{reason}" for reason in verdict["reasons"])

    actual_entries = {item.get("rva") for item in response.get("dynamicBasicBlockEntries") or []}
    if actual_entries != eligible_targets:
        violations.append("dynamicBasicBlockEntries-not-equal-eligible-targets")
    summary = response.get("summary") or {}
    if summary.get("providerEligibleSites") != eligible_count:
        violations.append("summary-providerEligibleSites-mismatch")
    if summary.get("observations") != len(observations):
        violations.append("summary-observations-mismatch")
    return {
        "status": "pass" if not violations else "fail",
        "observations": len(observations), "sites": len(seen_sites),
        "instructionCaptures": len(captures),
        "providerEligibleSites": eligible_count,
        "observationClasses": dict(sorted(collections.Counter(
            item.get("classification") for item in observations).items())),
        "violations": sorted(set(violations)),
    }


def make_request(site_rva, proof_type, image, image_sha256, *,
                 checkpoint_run=None, checkpoint_context_sha256=None,
                 role="any-proved", workspace=None, chunker="scripts/retdec_pe_chunked.py",
                 output_dir="out/decompiled/retdec"):
    workspace = Path(workspace or Path.cwd())
    if proof_type not in PROOF_TYPES:
        raise ValueError(f"unsupported proof type: {proof_type}")
    if role not in ROLES:
        raise ValueError(f"unsupported role: {role}")
    if not is_sha256(image_sha256):
        raise ValueError("lowercase image SHA256 required")
    if bool(checkpoint_run) != bool(checkpoint_context_sha256):
        raise ValueError("checkpoint run and contextSha256 must be supplied together")
    if checkpoint_context_sha256 and not is_sha256(checkpoint_context_sha256):
        raise ValueError("lowercase checkpoint context SHA256 required")
    site_rva = jint(parse_int(site_rva))
    image_path = resolve_path(image, workspace)
    image_info = {"path": path_reference(Path(image), workspace), "sha256": image_sha256}
    if image_path.is_file():
        image_info["fileSize"] = image_path.stat().st_size
    core = {
        "format": REQUEST_FORMAT,
        "siteRva": site_rva,
        "proofType": proof_type,
        "requestedRole": role if proof_type == "stack-role" else None,
        "image": image_info,
        "checkpoint": {
            "kind": ("existing-unicorn-observation" if checkpoint_run
                     else "existing-sidecar-site-state"),
            "run": checkpoint_run,
            "contextSha256": checkpoint_context_sha256,
            "required": True,
        },
        "constraints": {
            "addressModel": "RVA", "responseFormat": EVIDENCE_FORMAT,
            "providerEligibleOnly": True, "unknownPages": "forbid",
            "zeroFill": "forbid", "responseSha256": "required-at-validation",
            "witnessSetSha256": "required-at-validation",
            "maxWitnesses": MAX_WITNESSES, "maxTargets": MAX_TARGETS,
            "maxOverlayBytes": MAX_OVERLAY_BYTES,
            "maxRetdecSpan": MAX_RETDEC_SPAN,
            "chunker": str(chunker), "outputDir": str(output_dir),
        },
    }
    core["requestId"] = "ur-" + sha256_bytes(canonical(core).encode())[:24]
    return core


def unknown_result(request, response_path, reasons, *, response_sha256=None,
                   witness_sha256=None, audit_report=None, workspace=None,
                   diagnostics=None):
    workspace = workspace or Path.cwd()
    return {
        "format": RESULT_FORMAT, "status": "unknown",
        "requestId": request.get("requestId"), "siteRva": request.get("siteRva"),
        "proofType": request.get("proofType"),
        "response": {"path": path_reference(Path(response_path), workspace),
                     "sha256": response_sha256},
        "witnessSetSha256": witness_sha256,
        "sourceAudit": ({"status": audit_report.get("status"),
                         "violations": audit_report.get("violations", [])}
                        if audit_report else None),
        "eligibleEvidence": [], "retdecPlan": None,
        "proofManifest": None, "overlayDiagnostics": diagnostics,
        "reasons": sorted(set(reasons)),
        "policy": "unknown only; no eligible evidence, overlay, or RetDec command is authorized",
    }


def select_site_and_witnesses(request, response):
    sites = [site for site in response.get("controlFlowSites") or []
             if site.get("siteRva") == request["siteRva"]]
    if len(sites) != 1:
        return None, [], ["requested-site-missing-or-duplicated"]
    site = sites[0]
    observations = response.get("observations") or []
    ids_list = [item.get("observationId") for item in observations]
    if len(ids_list) != len(set(ids_list)):
        return site, [], ["response-observation-ids-duplicated"]
    by_id = {item.get("observationId"): item for item in observations}
    ids = site.get("observationIds") or []
    if not ids or len(ids) != len(set(ids)) or any(oid not in by_id for oid in ids):
        return site, [], ["site-observation-join-incomplete"]
    if len(ids) > MAX_WITNESSES:
        return site, [], ["witness-limit-exceeded"]
    witnesses = [by_id[oid] for oid in ids]
    checkpoint = request.get("checkpoint") or {}
    if checkpoint.get("required") is not True:
        return site, [], ["checkpoint-required-not-true"]
    if checkpoint.get("run") is not None:
        witnesses = [item for item in witnesses
                     if item.get("run") == checkpoint.get("run")
                     and item.get("contextSha256") == checkpoint.get("contextSha256")]
    if not witnesses:
        return site, [], ["checkpoint-not-found-in-response"]
    return site, witnesses, []


def provider_observation_matches(observation, source, target, classification, image_sha):
    if (observation.get("sourceRva") != source
            or observation.get("targetRva") != target
            or observation.get("classification") != classification
            or observation.get("imageSha256") != image_sha
            or observation.get("observationId") != observation_id(observation)):
        return False
    context = observation.get("context") or {}
    if (context.get("sha256") != context_hash(context)
            or observation.get("contextSha256") != context.get("sha256")):
        return False
    if classification == "static":
        return observation.get("staticTargetRva") == target
    return classification == "dynamic-verified" and clean_dynamic(observation)


def validate_single_target(response, site, witnesses):
    reasons = []
    image_sha = response["image"]["sha256"]
    image_size = parse_int(response["addressModel"]["imageSize"])
    targets = site.get("targets") or []
    if site.get("providerEligible") is not True:
        reasons.append("providerEligible-not-true")
    if site.get("classification") not in {"static", "dynamic-verified"}:
        reasons.append("provider-class-not-eligible")
    if len(targets) != 1 or site.get("targetRva") != targets[0]:
        return None, sorted(set(reasons + ["single-target-required"]))
    target = targets[0]
    if target is None or not 0 < parse_int(target) < image_size:
        reasons.append("target-outside-image-or-zero")
    kind = site.get("kind")
    if kind == "jmp" and site.get("classification") == "dynamic-verified":
        if (site.get("targetSetComplete") is not True
                or "targetCases" in site or "stateOperand" in site):
            reasons.append("provider-dynamic-singleton-jmp-completeness-missing")
    supporting = [item for item in witnesses if provider_observation_matches(
        item, site["siteRva"], target, site.get("classification"), image_sha)]
    if not supporting:
        reasons.append("provider-supporting-observation-missing")
    if kind == "ret":
        trampoline = site.get("stackTrampolineEvidence") or {}
        if (trampoline.get("targetStillUnresolved") is not False
                or not (trampoline.get("text") or "").startswith("push")):
            reasons.append("provider-ret-trampoline-proof-missing")
    if reasons:
        return None, sorted(set(reasons))
    return {
        "proofType": "control-flow-target", "siteRva": site["siteRva"],
        "kind": kind, "classification": site["classification"],
        "targetRva": target, "targets": targets, "providerEligible": True,
        "imageSha256": image_sha,
        "witnessObservationIds": sorted(item["observationId"] for item in supporting),
    }, []


def validate_target_set(response, site, witnesses):
    verdict = validate_target_set_proof(site, witnesses, response["image"]["sha256"])
    reasons = list(verdict["reasons"])
    if site.get("targetSetComplete") is not True:
        reasons.append("targetSetComplete-not-true")
    if site.get("providerEligible") is not True:
        reasons.append("providerEligible-not-true")
    if len(site.get("targets") or []) > MAX_TARGETS:
        reasons.append("target-limit-exceeded")
    if reasons:
        return None, sorted(set(reasons))
    return {
        "proofType": "control-flow-target-set", "siteRva": site["siteRva"],
        "kind": site["kind"], "classification": site["classification"],
        "targets": site["targets"], "targetCases": site.get("targetCases"),
        "targetSetComplete": True, "providerEligible": True,
        "targetSetProofSha256": verdict["proofSha256"],
        "imageSha256": response["image"]["sha256"],
        "witnessObservationIds": sorted(item["observationId"] for item in witnesses),
    }, []


def validate_stack_role(response, site, witnesses, requested_role):
    if len(witnesses) != 1:
        return None, ["stack-role-requires-one-checkpointed-witness"]
    observation = witnesses[0]
    slot = observation.get("stackSlot") or {}
    if slot.get("providerEligible") is not True:
        return None, ["stack-slot-address-proof-not-provider-eligible"]
    if not clean_dynamic(observation):
        return None, ["stack-role-underlying-dynamic-proof-not-clean"]
    captures = {item.get("captureId"): item
                for item in response.get("instructionCaptures") or []}
    verdict = validate_role_proof(observation, captures, response["image"]["sha256"])
    reasons = list(verdict["reasons"])
    if (verdict["status"] == "proved" and requested_role != "any-proved"
            and verdict.get("role") != requested_role):
        reasons.append("proved-role-does-not-match-request")
    if reasons:
        return None, sorted(set(reasons))
    role = verdict["role"]
    return {
        "proofType": "stack-role", "siteRva": site["siteRva"], "role": role,
        "roleProofSha256": verdict["proofSha256"],
        "displacement": slot.get("displacement"), "address": slot.get("address"),
        "providerEligible": True, "imageSha256": response["image"]["sha256"],
        "providerEffect": ("ABI stack reconstruction permitted" if role == "abi-frame"
                           else "role proved; non-ABI slot remains opaque in StackAnalysis"),
        "witnessObservationIds": [observation["observationId"]],
    }, []


def _legacy_instruction_capture(observation):
    data = observation.get("instructionBytes")
    context = observation.get("context") or {}
    capture = {
        "run": observation.get("run"), "seed": observation.get("seed"),
        "wave": observation.get("wave"), "step": observation.get("step"),
        "va": observation.get("sourceVa"), "rva": observation.get("sourceRva"),
        "length": observation.get("instructionSize"), "instructionBytes": data,
        "mnemonic": observation.get("mnemonic"), "text": observation.get("text"),
        "runtimeImageBase": observation.get("runtimeImageBase"),
        "imageSha256": observation.get("imageSha256"), "context": context,
        "contextSha256": observation.get("contextSha256"),
        "scratch-taint": observation.get("scratch-taint"),
        "transferObservationId": observation.get("observationId"),
        "instructionSha256": sha256_bytes(bytes.fromhex(data)) if data else None,
        "provenance": {
            "kind": "legacy-transfer-observation", "timing": "before-execution",
            "bytesReadFrom": "emulated-memory", "runtimeVa": observation.get("sourceVa"),
            "imageSha256": observation.get("imageSha256"),
            "contextSha256": observation.get("contextSha256"),
            "codePageOrigin": "image",
        },
        "captureId": "legacy-" + str(observation.get("observationId")),
    }
    return capture


def _overlay_entry(rva, captures, image_sha):
    by_data = collections.defaultdict(list)
    for capture in captures:
        by_data[capture["instructionBytes"]].append(capture)
    if len(by_data) != 1:
        return None, "different-dynamic-bytes-same-rva"
    data_hex = next(iter(by_data))
    group = by_data[data_hex]
    raw = bytes.fromhex(data_hex)
    if any((capture.get("mnemonic") == "decode-error") for capture in group):
        return None, "decode-error-capture"
    provenance = {canonical(item.get("provenance") or {}): item.get("provenance") or {}
                  for item in group}
    return {
        "rva": rva, "length": len(raw), "data": data_hex, "sha256": sha256_bytes(raw),
        "mnemonic": sorted({item.get("mnemonic") for item in group if item.get("mnemonic")})[0],
        "analysisEligible": True, "captureIds": sorted(item["captureId"] for item in group),
        "captureCount": len(group),
        "contextSha256": sorted({item.get("contextSha256") for item in group
                                 if item.get("contextSha256")}),
        "transferObservationIds": sorted({item["transferObservationId"] for item in group
                                          if item.get("transferObservationId")}),
        "imageSha256": image_sha,
        "provenance": [provenance[key] for key in sorted(provenance)],
        "note": "observed dynamic instruction bytes; not a CFG proof by itself",
    }, None


def bounded_overlay(response, response_sha256, evidence):
    wanted = {evidence["siteRva"], *(evidence.get("targets") or [])}
    if evidence.get("proofType") == "stack-role":
        wanted = {evidence["siteRva"]}
    captures = list(response.get("instructionCaptures") or [])
    if not captures:
        captures = [_legacy_instruction_capture(item)
                    for item in response.get("observations") or []]
    entries, omissions = [], []
    for rva in sorted(wanted, key=parse_int):
        group = [item for item in captures if item.get("rva") == rva]
        if not group:
            omissions.append({"rva": rva, "reasons": ["capture-missing"]})
            continue
        bad = sorted({reason for capture in group for reason in no_zero_fill_reasons(
            {"context": capture.get("context") or {},
             "scratch-taint": capture.get("scratch-taint") or {},
             "replay": {"missing": [], "error": None}}, capture)})
        if bad:
            omissions.append({"rva": rva, "reasons": bad})
            continue
        try:
            entry, conflict = _overlay_entry(rva, group, response["image"]["sha256"])
        except (KeyError, TypeError, ValueError):
            entry, conflict = None, "invalid-capture"
        if conflict:
            omissions.append({"rva": rva, "reasons": [conflict]})
        else:
            entries.append(entry)
    diagnostics = {
        "requestedRvas": sorted(wanted, key=parse_int), "omissions": omissions,
        "policy": "all requested site/target captures required; never substitute zero bytes",
    }
    if omissions:
        raise ProofRejected("bounded-overlay-incomplete", diagnostics=diagnostics)
    if sum(item["length"] for item in entries) > MAX_OVERLAY_BYTES:
        raise ProofRejected("overlay-byte-limit-exceeded", diagnostics=diagnostics)
    overlay = {
        "format": OVERLAY_FORMAT,
        "addressModel": copy.deepcopy(response["addressModel"]),
        "image": copy.deepcopy(response["image"]),
        "source": {
            "format": response["format"], "sha256": response_sha256,
            "kind": "bounded-request-site-and-targets",
            "captureScope": "request-whitelist",
        },
        "application": {
            "addressKey": "RVA", "originalModified": False,
            "rule": "Apply entry.data at ImageBase+RVA only when analysisEligible=true.",
            "overlap": "Distinct instruction entries may overlap; conflicting bytes are rejected.",
        },
        "entries": entries, "conflicts": [], "invalidCaptures": [],
        "summary": {
            "ranges": [{"startRva": item["rva"],
                        "endRvaExclusive": jint(parse_int(item["rva"]) + item["length"])}
                       for item in entries],
            "captures": sum(item["captureCount"] for item in entries),
            "validCaptures": sum(item["captureCount"] for item in entries),
            "invalidCaptures": 0, "uniqueCaptureRvas": len(entries),
            "overlayEntries": len(entries), "conflictingOrInvalidRvas": 0,
            "differentBytesConflicts": 0,
            "entryBytesWithOverlap": sum(item["length"] for item in entries),
            "uniqueByteCoverage": len({parse_int(item["rva"]) + offset
                                       for item in entries for offset in range(item["length"])}),
            "captureDigest": sha256_bytes(canonical(sorted(
                cid for item in entries for cid in item["captureIds"])).encode()),
            "allEligibleBytesMatchCaptures": True,
        },
        "limitations": [
            "Bounded to the request site and targets; no stability beyond captured contexts.",
            "Sparse unobserved bytes retain the verified analysis-image fallback.",
            "Unknown/zero-fill/conflicting/missing captures reject the whole requested overlay.",
        ],
    }
    return overlay, diagnostics


def validate_overlay(payload, image_path, image_sha256):
    if payload.get("format") != OVERLAY_FORMAT:
        raise ProofRejected("overlay-format-invalid")
    if (payload.get("addressModel") or {}).get("key") != "RVA":
        raise ProofRejected("overlay-address-model-not-rva")
    if (payload.get("image") or {}).get("sha256") != image_sha256:
        raise ProofRejected("overlay-image-sha256-mismatch")
    file_size = (payload.get("image") or {}).get("fileSize")
    if file_size is not None and int(file_size) != Path(image_path).stat().st_size:
        raise ProofRejected("overlay-image-file-size-mismatch")
    image_size = parse_int(payload["addressModel"]["imageSize"])
    for entry in payload.get("entries") or []:
        raw = bytes.fromhex(entry.get("data") or "")
        start = parse_int(entry["rva"])
        if (entry.get("analysisEligible") is not True or not raw
                or len(raw) != entry.get("length") or sha256_bytes(raw) != entry.get("sha256")
                or entry.get("imageSha256") != image_sha256
                or start < 0 or start + len(raw) > image_size):
            raise ProofRejected("overlay-entry-invalid")
    if payload.get("conflicts") or payload.get("invalidCaptures"):
        raise ProofRejected("overlay-conflicts-or-invalid-captures-present")


def witness_descriptor(observation):
    return {
        "observationId": observation.get("observationId"), "run": observation.get("run"),
        "sourceRva": observation.get("sourceRva"), "targetRva": observation.get("targetRva"),
        "contextSha256": observation.get("contextSha256"),
        "instructionCaptureId": observation.get("instructionCaptureId"),
        "instructionSha256": (sha256_bytes(bytes.fromhex(observation["instructionBytes"]))
                              if observation.get("instructionBytes") else None),
        "observationSha256": sha256_bytes(canonical(observation).encode()),
    }


def make_retdec_plan(request, response_path, response_sha256, evidence, *,
                     overlay_path=None, overlay_sha256=None, workspace=None):
    workspace = workspace or Path.cwd()
    rvas = ([evidence["siteRva"]] if evidence.get("proofType") == "stack-role"
            else [evidence["siteRva"], *(evidence.get("targets") or [])])
    values = [parse_int(item) for item in rvas]
    lo = min(values) & ~(PAGE - 1)
    hi = (max(values) + PAGE) & ~(PAGE - 1)
    image_size = parse_int(request["image"]["imageSize"])
    hi = min(hi, image_size)
    if hi <= lo:
        raise ProofRejected("retdec-range-empty")
    if hi - lo > MAX_RETDEC_SPAN:
        raise ProofRejected("retdec-range-exceeds-16-mib")
    constraints = request.get("constraints") or {}
    output_dir = constraints.get("outputDir") or "out/decompiled/retdec"
    chunker = constraints.get("chunker") or "scripts/retdec_pe_chunked.py"
    output = (Path(output_dir) /
              f"unicorn_retdec_{request['siteRva'][2:]}_{request['proofType']}.c")
    command = [
        "python3", str(chunker), request["image"]["path"], f"{lo:#x}-{hi:#x}",
        output.as_posix(), "--chunk-mb", "1", "--workers", "1",
        "--mem-per-worker-mb", "8000", "--griffin-sidecar",
        path_reference(Path(response_path), workspace), "--fixed-windows",
    ]
    if overlay_path is not None:
        command += ["--griffin-overlay", path_reference(Path(overlay_path), workspace)]
    capture_ids = sorted({item.get("instructionCaptureId") for item in evidence["witnesses"]
                          if item.get("instructionCaptureId")})
    manifest = {
        "format": MANIFEST_FORMAT, "requestId": request["requestId"],
        "siteRva": request["siteRva"], "proofType": request["proofType"],
        "imageSha256": request["image"]["sha256"],
        "responseSha256": response_sha256,
        "witnessSetSha256": evidence["witnessSetSha256"],
        "observationIds": sorted(item["observationId"] for item in evidence["witnesses"]),
        "captureIds": capture_ids,
        "maxRetdecSpan": MAX_RETDEC_SPAN,
    }
    if overlay_path is not None:
        manifest["overlaySha256"] = overlay_sha256
        manifest["overlayCaptureIds"] = sorted({
            cid for item in evidence["overlayEntries"] for cid in item["captureIds"]})
    return {
        "format": PLAN_FORMAT, "status": "planned-not-executed",
        "requestId": request["requestId"], "selectedRangeRva": f"{lo:#x}-{hi:#x}",
        "image": request["image"],
        "sidecar": {"path": path_reference(Path(response_path), workspace),
                    "sha256": response_sha256},
        "overlay": ({"path": path_reference(Path(overlay_path), workspace),
                     "sha256": overlay_sha256} if overlay_path is not None else None),
        "outputFuture": output.as_posix(), "command": command,
        "proofManifest": manifest,
        "execution": {"performed": False, "campaign": False,
                      "note": "Command only. Run deliberately with one worker outside validation."},
    }


def _validate_response(request, response_path, response_sha256, witness_sha256, *,
                       overlay_path=None, workspace=None):
    workspace = Path(workspace or Path.cwd())
    response_path = resolve_path(response_path, workspace)
    if request.get("format") != REQUEST_FORMAT or not request.get("requestId"):
        return unknown_result(request, response_path, ["request-format-or-id-invalid"],
                              workspace=workspace)
    if request.get("proofType") not in PROOF_TYPES:
        return unknown_result(request, response_path, ["unsupported-proof-type"],
                              workspace=workspace)
    if not is_sha256(response_sha256) or not is_sha256(witness_sha256):
        return unknown_result(request, response_path,
                              ["response-and-witness-sha256-are-mandatory-lowercase-hex"],
                              workspace=workspace)
    actual_response_sha = sha256_file(response_path)
    if actual_response_sha != response_sha256:
        return unknown_result(request, response_path, ["response-sha256-mismatch"],
                              response_sha256=actual_response_sha, workspace=workspace)
    response = load_json(response_path)
    image_path = resolve_path(request["image"]["path"], workspace)
    actual_image_sha = sha256_file(image_path)
    if actual_image_sha != request["image"].get("sha256"):
        return unknown_result(request, response_path, ["request-image-sha256-mismatch"],
                              response_sha256=actual_response_sha, workspace=workspace)
    image_size = image_path.stat().st_size
    if (request["image"].get("fileSize") is not None
            and int(request["image"]["fileSize"]) != image_size):
        return unknown_result(request, response_path, ["request-image-file-size-mismatch"],
                              response_sha256=actual_response_sha, workspace=workspace)
    if response.get("format") != EVIDENCE_FORMAT:
        return unknown_result(request, response_path, ["response-format-not-evidence-v2"],
                              response_sha256=actual_response_sha, workspace=workspace)
    response_image = response.get("image") or {}
    if response_image.get("sha256") != actual_image_sha:
        return unknown_result(request, response_path, ["response-image-sha256-mismatch"],
                              response_sha256=actual_response_sha, workspace=workspace)
    if (response_image.get("fileSize") is not None
            and int(response_image["fileSize"]) != image_size):
        return unknown_result(request, response_path, ["response-image-file-size-mismatch"],
                              response_sha256=actual_response_sha, workspace=workspace)
    # RVA-layout dumps use file offsets as RVAs.  Keep a bounded VA/RVA join.
    declared_size = parse_int((response.get("addressModel") or {})["imageSize"])
    if declared_size <= 0:
        raise ProofRejected("response-image-size-invalid")
    request["image"]["imageSize"] = jint(declared_size)

    audit_report = audit_sidecar(response, actual_image_sha, image_path)
    if audit_report.get("status") != "pass":
        return unknown_result(request, response_path, ["response-sidecar-audit-failed"],
                              response_sha256=actual_response_sha,
                              audit_report=audit_report, workspace=workspace)
    site, witnesses, reasons = select_site_and_witnesses(request, response)
    if reasons:
        return unknown_result(request, response_path, reasons,
                              response_sha256=actual_response_sha,
                              audit_report=audit_report, workspace=workspace)
    actual_witness_sha = witness_set_sha256(witnesses)
    if actual_witness_sha != witness_sha256:
        reasons.append("witness-set-sha256-mismatch")
    captures = {item.get("captureId"): item
                for item in response.get("instructionCaptures") or []}
    for observation in witnesses:
        reasons.extend(no_zero_fill_reasons(
            observation, captures.get(observation.get("instructionCaptureId"))))
        if observation.get("imageSha256") != actual_image_sha:
            reasons.append("witness-image-sha256-mismatch")
        if observation.get("observationId") != observation_id(observation):
            reasons.append("witness-observation-id-mismatch")
    if reasons:
        return unknown_result(request, response_path, reasons,
                              response_sha256=actual_response_sha,
                              witness_sha256=actual_witness_sha,
                              audit_report=audit_report, workspace=workspace)
    proof_type = request["proofType"]
    if proof_type == "control-flow-target":
        evidence, proof_reasons = validate_single_target(response, site, witnesses)
    elif proof_type == "control-flow-target-set":
        evidence, proof_reasons = validate_target_set(response, site, witnesses)
    else:
        evidence, proof_reasons = validate_stack_role(
            response, site, witnesses, request.get("requestedRole") or "any-proved")
    if proof_reasons:
        return unknown_result(request, response_path, proof_reasons,
                              response_sha256=actual_response_sha,
                              witness_sha256=actual_witness_sha,
                              audit_report=audit_report, workspace=workspace)
    evidence["witnessSetSha256"] = actual_witness_sha
    evidence["witnesses"] = [witness_descriptor(item) for item in witnesses]
    overlay_diagnostics = None
    overlay = None
    if overlay_path is not None:
        overlay_path = resolve_path(overlay_path, workspace)
        overlay, overlay_diagnostics = bounded_overlay(response, actual_response_sha, evidence)
        validate_overlay(overlay, image_path, actual_image_sha)
        overlay_sha = sha256_bytes(json_text(overlay).encode())
        evidence["overlayEntries"] = copy.deepcopy(overlay["entries"])
    else:
        overlay_sha = None
    # Construct the bounded plan before creating an overlay file.  If the plan
    # itself is rejected (for example >16 MiB), no partial artifact remains.
    plan = make_retdec_plan(request, response_path, actual_response_sha, evidence,
                            overlay_path=overlay_path, overlay_sha256=overlay_sha,
                            workspace=workspace)
    if overlay is not None:
        saved_overlay_sha = save_json(overlay_path, overlay)
        if saved_overlay_sha != overlay_sha:
            raise ProofRejected("overlay-save-sha256-mismatch")
    evidence.pop("overlayEntries", None)
    return {
        "format": RESULT_FORMAT, "status": "accepted",
        "requestId": request["requestId"], "siteRva": request["siteRva"],
        "proofType": proof_type,
        "response": {"path": path_reference(response_path, workspace),
                     "sha256": actual_response_sha},
        "imageSha256": actual_image_sha, "witnessSetSha256": actual_witness_sha,
        "sourceAudit": {"status": "pass", "violations": []},
        "eligibleEvidence": [evidence], "overlayDiagnostics": overlay_diagnostics,
        "retdecPlan": plan, "proofManifest": plan["proofManifest"], "reasons": [],
        "limits": [
            "Proof is local to supplied contexts; no implicit exhaustiveness.",
            "No Unicorn or RetDec execution occurred.",
            "The chunker path is a plan contract and is not required by validation/self-test.",
        ],
    }


def validate_response(request, response_path, response_sha256, witness_sha256, *,
                      overlay_path=None, workspace=None):
    """Public fail-closed API; expected data errors become unknown, never partial output."""
    workspace = Path(workspace or Path.cwd())
    try:
        # Do not mutate the caller's request when adding the derived imageSize.
        request = copy.deepcopy(request)
        return _validate_response(request, response_path, response_sha256, witness_sha256,
                                  overlay_path=overlay_path, workspace=workspace)
    except ProofRejected as exc:
        return unknown_result(request, response_path, exc.reasons, workspace=workspace,
                              diagnostics=exc.diagnostics)
    except (OSError, KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return unknown_result(request, response_path,
                              [f"validation-error:{type(exc).__name__}"], workspace=workspace)


# ---------------------------------------------------------------------------
# Synthetic, autonomous tests.  No external sample or optional dependency.


def _test_context(run, *, rsp="0x7000", memory=None):
    context = {"capture": "pre-instruction", "complete": True,
               "registers": {"rsp": rsp, "rip": "0x140000000"}, "memory": memory or []}
    context["sha256"] = context_hash(context)
    return context


def _test_capture(observation, image_sha, *, rva=None, data=None, run=None,
                  step=None, mnemonic=None):
    rva = rva or observation["sourceRva"]
    source_va = parse_int(observation["sourceVa"])
    source_rva = parse_int(observation["sourceRva"])
    va = jint(parse_int(observation["runtimeImageBase"]) + parse_int(rva))
    raw = data or observation["instructionBytes"]
    capture = {
        "run": run or observation["run"], "seed": observation.get("seed"),
        "wave": observation.get("wave"),
        "step": observation.get("step") if step is None else step,
        "va": va, "rva": rva, "baseUsed": "runtime", "length": len(bytes.fromhex(raw)),
        "instructionBytes": raw, "instructionSha256": sha256_bytes(bytes.fromhex(raw)),
        "mnemonic": mnemonic or observation["mnemonic"], "text": mnemonic or observation["text"],
        "runtimeImageBase": observation["runtimeImageBase"], "imageSha256": image_sha,
        "context": copy.deepcopy(observation["context"]),
        "contextSha256": observation["contextSha256"],
        "scratch-taint": {"tainted": False, "unknown": False, "reads": [], "events": []},
        "transferObservationId": observation.get("observationId"),
        "provenance": {
            "kind": "unicorn-code-hook", "timing": "before-execution",
            "bytesReadFrom": "emulated-memory", "runtimeVa": va,
            "codePage": jint(parse_int(va) & ~(PAGE - 1)), "codePageOrigin": "image",
            "imageSha256": image_sha, "contextSha256": observation["contextSha256"],
        },
    }
    capture["captureId"] = instruction_capture_id(capture)
    return capture


def _refresh_summary(response):
    sites = response["controlFlowSites"]
    observations = response["observations"]
    eligible = [site for site in sites if site.get("providerEligible") is True]
    targets = sorted({target for site in eligible for target in site["targets"]}, key=parse_int)
    response["dynamicBasicBlockEntries"] = [
        {"rva": target, "provenance": "provider-eligible-control-target",
         "doNotInferFunctionBoundary": True} for target in targets]
    response["summary"] = {
        "observations": len(observations), "providerEligibleSites": len(eligible),
        "providerRejectedSites": len(sites) - len(eligible),
        "observationClasses": dict(sorted(collections.Counter(
            item["classification"] for item in observations).items())),
    }


def make_synthetic_response(image_path, workspace):
    """Create accepted singleton/CFF/role proofs plus real negative-control material."""
    image_sha = sha256_file(image_path)
    base = 0x140000000
    observations, captures, sites = [], [], []

    def add(source, target, run, *, mnemonic="call", text="call rax", raw="ffd0",
            state=None, role=False):
        source_va, target_va = base + source, base + target
        memory = []
        if role:
            memory = [{"address": "0x7020", "size": 8,
                       "data": target_va.to_bytes(8, "little").hex(), "provenance": "stack"}]
        context = _test_context(run, memory=memory)
        observation = {
            "run": run, "seed": "0x1", "wave": 1, "step": len(observations) + 1,
            "sourceVa": jint(source_va), "sourceRva": jint(source), "sourceBase": "runtime",
            "targetVa": jint(target_va), "targetRva": jint(target), "targetBase": "runtime",
            "mnemonic": mnemonic, "text": text, "instructionSize": len(bytes.fromhex(raw)),
            "instructionBytes": raw, "rsp": "0x7000", "runtimeImageBase": jint(base),
            "imageSha256": image_sha, "context": context, "contextSha256": context["sha256"],
            "scratch-taint": {"tainted": False, "unknown": False, "reads": [], "events": []},
            "replay": {"status": "match", "actualTargetVa": jint(target_va),
                       "actualTargetRva": jint(target), "missing": [], "error": None},
            "staticTargetRva": None, "classification": "dynamic-verified",
        }
        if state is not None:
            observation["stateValue"] = jint(state)
        observation["observationId"] = observation_id(observation)
        capture = _test_capture(observation, image_sha)
        observation["instructionCaptureId"] = capture["captureId"]
        captures.append(capture)
        captures.append(_test_capture(observation, image_sha, rva=jint(target), data="53",
                                      run=run + "-target", step=1000 + len(observations),
                                      mnemonic="push"))
        observations.append(observation)
        return observation

    single = add(0x100, 0x2000, "run-call")
    set_a = add(0x300, 0x2100, "run-set-a", mnemonic="jmp", text="jmp rax",
                raw="ffe0", state=0)
    set_b = add(0x300, 0x2200, "run-set-b", mnemonic="jmp", text="jmp rax",
                raw="ffe0", state=1)
    role = add(0x400, 0x2300, "run-role", text="call qword ptr [rsp + 0x20]",
               raw="ff542420", role=True)

    # Explicit vm-spill role proof; displacement alone would remain unknown.
    role["stackSlot"] = {"role": "vm-spill", "roleProven": True, "displacement": "0x20",
                         "address": "0x7020"}
    role_proof = {
        "status": "proved", "kind": "vm-spill-dataflow", "role": "vm-spill",
        "imageSha256": image_sha, "sourceRva": role["sourceRva"],
        "observationId": role["observationId"], "contextSha256": role["contextSha256"],
        "instructionSha256": sha256_bytes(bytes.fromhex(role["instructionBytes"])),
        "displacement": "0x20",
        "evidence": {
            "captureClass": "emulated-real-input",
            "writerCapture": {"captureId": "writer-1", "contextSha256": "a" * 64,
                              "postContextSha256": "b" * 64, "address": "0x7020", "size": 8,
                              "replay": {"status": "match", "postContext": {"status": "match"}}},
            "activation": {"activationId": "activation-1", "entryCaptureId": "entry-1",
                           "exitCaptureId": "exit-1"},
            "vmSpill": {"contextId": "vm-1", "slotId": "slot-1", "reloadCaptureId": "reload-1",
                        "defUseChainComplete": True},
            "negativeControl": {"status": "pass", "kind": "remove-writer",
                                "observationId": role["observationId"]},
        },
    }
    role_proof["proofSha256"] = proof_hash(role_proof)
    role["stackRoleProof"] = role_proof
    role["stackSlot"]["roleProof"] = role_proof
    role["stackSlot"] = derive_stack_slot(role)

    sites.append({"siteRva": single["sourceRva"], "kind": "call",
                  "targetRva": single["targetRva"], "targets": [single["targetRva"]],
                  "classification": "dynamic-verified", "providerEligible": True,
                  "observationIds": [single["observationId"]], "stackTrampolineEvidence": None})
    targets = sorted([set_a["targetRva"], set_b["targetRva"]], key=parse_int)
    set_observations = sorted([set_a, set_b], key=lambda item: item["observationId"])
    target_cases = sorted([
        {"targetRva": item["targetRva"], "stateValue": item["stateValue"],
         "observationId": item["observationId"], "imageSha256": image_sha,
         "contextSha256": item["contextSha256"],
         "replay": {"status": "match", "actualTargetRva": item["targetRva"]}}
        for item in (set_a, set_b)], key=lambda item: parse_int(item["targetRva"]))
    set_site = {"siteRva": "0x300", "kind": "jmp", "targetRva": None, "targets": targets,
                "classification": "dynamic-verified", "providerEligible": True,
                "observationIds": [item["observationId"] for item in set_observations],
                "targetSetComplete": True, "stateOperand": "pseudo-arg",
                "targetCases": target_cases, "stackTrampolineEvidence": None}
    target_proof = {
        "status": "proved", "kind": "exhaustive-state-enumeration",
        "imageSha256": image_sha, "siteRva": "0x300", "targets": targets,
        "observationIds": sorted(item["observationId"] for item in (set_a, set_b)),
        "evidence": {
            "captureClass": "emulated-real-input",
            "domain": {"kind": "finite-state", "complete": True, "entryCount": 2,
                       "entries": [{"stateValue": "0x0", "targetRva": set_a["targetRva"]},
                                   {"stateValue": "0x1", "targetRva": set_b["targetRva"]}]},
            "negativeControl": {"status": "pass", "kind": "omit-domain-state",
                                "observationId": set_a["observationId"]},
        },
    }
    target_proof["proofSha256"] = proof_hash(target_proof)
    set_site["targetSetProof"] = target_proof
    sites.append(set_site)
    sites.append({"siteRva": role["sourceRva"], "kind": "call",
                  "targetRva": role["targetRva"], "targets": [role["targetRva"]],
                  "classification": "dynamic-verified", "providerEligible": True,
                  "observationIds": [role["observationId"]], "stackTrampolineEvidence": None})
    response = {
        "format": EVIDENCE_FORMAT,
        "addressModel": {"key": "RVA", "staticImageBase": jint(base),
                         "runtimeImageBase": jint(base), "preferredTraceBase": jint(base),
                         "imageSize": jint(image_path.stat().st_size)},
        "image": {"path": path_reference(image_path, workspace), "sha256": image_sha,
                  "fileSize": image_path.stat().st_size,
                  "mappedSize": image_path.stat().st_size, "layout": "rva"},
        "source": {"kind": "inline-synthetic-selftest"},
        "observations": observations, "instructionCaptures": captures,
        "controlFlowSites": sites,
    }
    _refresh_summary(response)
    return response


def _request_for(response, image_path, workspace, site, proof_type, *, run=None,
                 context=None, role="any-proved"):
    return make_request(site, proof_type, image_path, response["image"]["sha256"],
                        checkpoint_run=run, checkpoint_context_sha256=context,
                        role=role, workspace=workspace)


def run_self_tests(output_dir=None):
    """Run light deterministic tests; optional output_dir contains demo artifacts."""
    checks = {"count": 0}
    cases = []

    def check(condition, label):
        checks["count"] += 1
        if not condition:
            raise AssertionError(label)

    def record(name, result, expected_reason=None):
        check(result["status"] in {"accepted", "unknown"}, name + ":verdict")
        if result["status"] == "unknown":
            check(not result["eligibleEvidence"] and result["retdecPlan"] is None,
                  name + ":fail-closed")
            if expected_reason:
                check(expected_reason in result["reasons"], name + ":reason")
        cases.append({"name": name, "status": result["status"],
                      "reasons": result["reasons"],
                      "eligibleEvidence": len(result["eligibleEvidence"]),
                      "retdecCommandPlanned": result["retdecPlan"] is not None})

    with tempfile.TemporaryDirectory(prefix="urintegrate-selftest-") as temporary_name:
        temporary = Path(temporary_name)
        workspace = temporary / "workspace"
        workspace.mkdir()
        image_path = workspace / "image.bin"
        # Non-zero synthetic bytes make accidental zero substitution visible.
        image_path.write_bytes(bytes((index % 255) + 1 for index in range(0x5000)))
        response = make_synthetic_response(image_path, workspace)
        response_path = workspace / "response.json"
        response_sha = save_json(response_path, response)
        audit = audit_sidecar(response, response["image"]["sha256"])
        check(audit["status"] == "pass", "synthetic response audit: " + repr(audit))
        single = next(item for item in response["observations"] if item["sourceRva"] == "0x100")
        request = _request_for(response, image_path, workspace, "0x100", "control-flow-target",
                               run=single["run"], context=single["contextSha256"])
        request_path = workspace / "request.json"
        save_json(request_path, request)
        witness_sha = witness_set_sha256([single])
        overlay_path = workspace / "overlay.json"
        accepted = validate_response(request, response_path, response_sha, witness_sha,
                                     overlay_path=overlay_path, workspace=workspace)
        check(accepted["status"] == "accepted", "accepted singleton: " + repr(accepted))
        check(accepted["eligibleEvidence"][0]["targetRva"] == "0x2000", "singleton target")
        check(accepted["retdecPlan"]["execution"]["performed"] is False, "no execution")
        check("--fixed-windows" in accepted["retdecPlan"]["command"], "fixed windows")
        check("--griffin-overlay" in accepted["retdecPlan"]["command"], "overlay command")
        overlay = load_json(overlay_path)
        check({item["rva"] for item in overlay["entries"]} == {"0x100", "0x2000"},
              "bounded overlay")
        validate_overlay(overlay, image_path, response["image"]["sha256"])
        checks["count"] += 1
        check(accepted["proofManifest"]["overlayCaptureIds"], "capture whitelist")
        check(not str(temporary) in json_text(accepted), "relocatable accepted paths")
        repeated = validate_response(request, response_path, response_sha, witness_sha,
                                     overlay_path=overlay_path, workspace=workspace)
        check(json_text(repeated) == json_text(accepted), "deterministic validation")
        record("accepted-control-flow-target-and-bounded-overlay", accepted)

        # A complete CFF domain is accepted; this is intentionally new coverage,
        # not a repeat of the PoC's incomplete-targetSet-only test.
        set_request = _request_for(response, image_path, workspace, "0x300",
                                   "control-flow-target-set")
        set_site = next(item for item in response["controlFlowSites"] if item["siteRva"] == "0x300")
        set_witnesses = [item for item in response["observations"]
                         if item["observationId"] in set_site["observationIds"]]
        set_result = validate_response(set_request, response_path, response_sha,
                                       witness_set_sha256(set_witnesses), workspace=workspace)
        check(set_result["status"] == "accepted", "accepted target set: " + repr(set_result))
        check(set_result["eligibleEvidence"][0]["targetSetComplete"] is True, "complete target set")
        record("accepted-complete-control-flow-target-set", set_result)

        role_obs = next(item for item in response["observations"] if item["sourceRva"] == "0x400")
        role_request = _request_for(response, image_path, workspace, "0x400", "stack-role",
                                    run=role_obs["run"], context=role_obs["contextSha256"],
                                    role="vm-spill")
        role_result = validate_response(role_request, response_path, response_sha,
                                        witness_set_sha256([role_obs]), workspace=workspace)
        check(role_result["status"] == "accepted", "accepted role: " + repr(role_result))
        check(role_result["eligibleEvidence"][0]["role"] == "vm-spill", "vm-spill proof")
        record("accepted-explicit-vm-spill-role-proof", role_result)

        bad_image_request = copy.deepcopy(request)
        bad_image_request["image"]["sha256"] = "0" * 64
        bad_image = validate_response(bad_image_request, response_path, response_sha, witness_sha,
                                      workspace=workspace)
        record("rejected-image-sha256", bad_image, "request-image-sha256-mismatch")
        bad_response = validate_response(request, response_path, "0" * 64, witness_sha,
                                         workspace=workspace)
        record("rejected-response-sha256", bad_response, "response-sha256-mismatch")
        bad_witness = validate_response(request, response_path, response_sha, "0" * 64,
                                        workspace=workspace)
        record("rejected-witness-sha256", bad_witness, "witness-set-sha256-mismatch")

        def mutated_result(name, mutate, req=request, overlay=False, expected=None):
            changed = copy.deepcopy(response)
            mutate(changed)
            _refresh_summary(changed)
            path = workspace / (name + ".json")
            sha = save_json(path, changed)
            selected_site, selected, selection_reasons = select_site_and_witnesses(req, changed)
            digest = witness_set_sha256(selected) if not selection_reasons else "0" * 64
            result = validate_response(req, path, sha, digest,
                                       overlay_path=(workspace / (name + ".overlay.json"))
                                       if overlay else None, workspace=workspace)
            record(name, result, expected)
            return result

        mutated_result("rejected-unknown-page",
                       lambda item: next(o for o in item["observations"]
                                         if o["observationId"] == single["observationId"])
                       ["scratch-taint"].update(unknown=True))
        mutated_result("rejected-incomplete-replay",
                       lambda item: next(o for o in item["observations"]
                                         if o["observationId"] == single["observationId"])
                       ["replay"].update(status="missing-context",
                                         missing=[{"address": "0xdead"}], error=None))
        mutated_result("rejected-zero-fill-instruction-page",
                       lambda item: next(c for c in item["instructionCaptures"]
                                         if c["captureId"] == single["instructionCaptureId"])
                       ["provenance"].update(codePageOrigin="zero-fill"))

        def incomplete_set(item):
            site = next(s for s in item["controlFlowSites"] if s["siteRva"] == "0x300")
            site.update(targetSetComplete=False, providerEligible=False,
                        classification="ambiguous")
        mutated_result("rejected-incomplete-target-set", incomplete_set, req=set_request,
                       expected="targetSetComplete-not-true")

        def missing_role(item):
            observation = next(o for o in item["observations"] if o["sourceRva"] == "0x400")
            observation.pop("stackRoleProof", None)
            prior = copy.deepcopy(observation["stackSlot"])
            prior.update(role="unknown", roleProven=False)
            prior.pop("roleProof", None)
            observation["stackSlot"] = prior
            observation["stackSlot"] = derive_stack_slot(observation)
        mutated_result("rejected-missing-role-proof", missing_role, req=role_request,
                       expected="explicit-role-proof-missing")

        def conflicting_overlay(item):
            target_capture = next(c for c in item["instructionCaptures"]
                                  if c["rva"] == "0x2000")
            conflict = copy.deepcopy(target_capture)
            conflict.update(run="conflicting-capture", step=9999,
                            instructionBytes="90", length=1,
                            instructionSha256=sha256_bytes(b"\x90"), mnemonic="nop")
            conflict["captureId"] = instruction_capture_id(conflict)
            item["instructionCaptures"].append(conflict)
        mutated_result("rejected-conflicting-requested-overlay", conflicting_overlay,
                       overlay=True, expected="bounded-overlay-incomplete")

        # Missing target captures are also fatal when an overlay was requested.
        def missing_target_capture(item):
            item["instructionCaptures"] = [c for c in item["instructionCaptures"]
                                           if c["rva"] != "0x2000"]
        mutated_result("rejected-missing-requested-overlay-capture", missing_target_capture,
                       overlay=True, expected="bounded-overlay-incomplete")

        # A copied file has no access to the original checkout.  Exercise both
        # request and validate CLIs from an unrelated cwd with stdlib Python.
        fork_root = temporary / "unrelated-fork"
        copied = fork_root / "scripts" / "unicorn_retdec_orchestrator.py"
        copied.parent.mkdir(parents=True)
        shutil.copy2(Path(__file__).resolve(), copied)
        portable_request = fork_root / "portable.request.json"
        command = [sys.executable, str(copied), "request", "--workspace", str(workspace),
                   "--site-rva", "0x100", "--proof-type", "control-flow-target",
                   "--image", "image.bin", "--image-sha256", response["image"]["sha256"],
                   "--checkpoint-run", single["run"], "--checkpoint-context-sha256",
                   single["contextSha256"], "--output", str(portable_request)]
        completed = subprocess.run(command, cwd=fork_root, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, timeout=20, check=False)
        check(completed.returncode == 0, "copied request CLI: " + completed.stderr)
        portable_result_path = fork_root / "portable.result.json"
        command = [sys.executable, str(copied), "validate", "--workspace", str(workspace),
                   "--request", str(portable_request), "--response", "response.json",
                   "--response-sha256", response_sha, "--witness-sha256", witness_sha,
                   "--overlay-output", str(workspace / "portable.overlay.json"),
                   "--output", str(portable_result_path)]
        completed = subprocess.run(command, cwd=fork_root, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, timeout=20, check=False)
        check(completed.returncode == 0, "copied validate CLI: " + completed.stderr)
        portable = load_json(portable_result_path)
        check(portable["status"] == "accepted", "copied module accepted")
        check(str(temporary) not in json_text(portable), "copied module emits relative paths")
        cases.append({"name": "copied-standalone-module-outside-project", "status": "pass",
                      "retdecExecuted": False, "unicornExecuted": False})

        if output_dir is not None:
            output_dir = Path(output_dir)
            save_json(output_dir / "vgk_agent_URINTEGRATE_request.json", request)
            save_json(output_dir / "vgk_agent_URINTEGRATE_accepted.json", accepted)
            save_json(output_dir / "vgk_agent_URINTEGRATE_plan.json", accepted["retdecPlan"])
            save_json(output_dir / "vgk_agent_URINTEGRATE_overlay.json", overlay)

    return {
        "format": "unicornretdec-portable-selftest-v1", "status": "pass",
        "assertions": checks["count"], "cases": cases,
        "stdlibOnly": True, "externalFixtures": False,
        "retdecExecuted": False, "unicornExecuted": False, "forkModified": False,
        "coverage": [
            "accepted singleton, complete target set, and explicit vm-spill roleProof",
            "image/response/witness SHA256 rejection and deterministic artifacts",
            "unknown pages, zero-fill pages, incomplete replay/proofs, missing/conflicting overlay captures",
            "copy-as-scripts/unicorn_retdec_orchestrator.py from an unrelated cwd",
        ],
        "limitations": [
            "Synthetic fixtures validate orchestration logic, not Unicorn semantics or generated C quality.",
            "SHA256 integrity is not a signature; trusted hash exchange remains required.",
            "The generated chunker command is planned only and is never executed by self-test.",
        ],
    }


def cmd_request(args):
    request = make_request(args.site_rva, args.proof_type, args.image, args.image_sha256,
                           checkpoint_run=args.checkpoint_run,
                           checkpoint_context_sha256=args.checkpoint_context_sha256,
                           role=args.role, workspace=args.workspace, chunker=args.chunker,
                           output_dir=args.output_dir)
    save_json(args.output, request)
    print(json_text(request), end="")
    return 0


def cmd_validate(args):
    request_path = resolve_path(args.request, args.workspace)
    request = load_json(request_path)
    result = validate_response(request, args.response, args.response_sha256,
                               args.witness_sha256, overlay_path=args.overlay_output,
                               workspace=args.workspace)
    if args.plan_output and result.get("retdecPlan"):
        save_json(args.plan_output, result["retdecPlan"])
    if args.output:
        save_json(args.output, result)
    print(json_text(result), end="")
    return 0 if result["status"] == "accepted" else 3


def cmd_self_test(args):
    report = run_self_tests(args.artifact_dir)
    if args.output:
        save_json(args.output, report)
    print(json_text(report), end="")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    request = sub.add_parser("request", help="create a bounded proof request")
    request.add_argument("--workspace", type=Path, default=Path.cwd())
    request.add_argument("--site-rva", required=True)
    request.add_argument("--proof-type", choices=PROOF_TYPES, required=True)
    request.add_argument("--image", required=True)
    request.add_argument("--image-sha256", required=True)
    request.add_argument("--checkpoint-run")
    request.add_argument("--checkpoint-context-sha256")
    request.add_argument("--role", choices=ROLES, default="any-proved")
    request.add_argument("--chunker", default="scripts/retdec_pe_chunked.py")
    request.add_argument("--output-dir", default="out/decompiled/retdec")
    request.add_argument("--output", type=Path, required=True)
    request.set_defaults(func=cmd_request)
    validate = sub.add_parser("validate", help="validate evidence and plan, never execute RetDec")
    validate.add_argument("--workspace", type=Path, default=Path.cwd())
    validate.add_argument("--request", type=Path, required=True)
    validate.add_argument("--response", required=True)
    validate.add_argument("--response-sha256", required=True)
    validate.add_argument("--witness-sha256", required=True)
    validate.add_argument("--overlay-output")
    validate.add_argument("--plan-output", type=Path)
    validate.add_argument("--output", type=Path)
    validate.set_defaults(func=cmd_validate)
    self_test = sub.add_parser("self-test", help="autonomous synthetic accept/reject tests")
    self_test.add_argument("--output", type=Path)
    self_test.add_argument("--artifact-dir", type=Path,
                           help="optional portable accepted/request/plan/overlay demo artifacts")
    self_test.set_defaults(func=cmd_self_test)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
