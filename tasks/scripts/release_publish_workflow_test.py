# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Static checks that stable publication can be retried for an existing tag.

Run via `mise run test:release-workflows`. A retry dispatches the current
workflow against an older release commit, so publish logic must not be loaded
from that commit's checkout.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_SHA = "${{ github.workflow_sha }}"
SOURCE_SHA = "${{ inputs.source-sha }}"

# Environment setup only; it does not decide what gets published.
SOURCE_ACTIONS = {"./.github/actions/setup-nix"}


def load(path: str) -> dict:
    return yaml.load((ROOT / path).read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


PUBLISH_WORKFLOWS = (
    ".github/workflows/release-publish.yml",
    ".github/workflows/sdk-go-tag.yml",
    ".github/workflows/sdk-typescript-publish.yml",
    ".github/workflows/snap-publish.yml",
    ".github/workflows/wheel-publish.yml",
)


def publish_jobs() -> dict:
    return load(".github/workflows/release-publish.yml")["jobs"]


def all_publish_jobs() -> dict:
    return {
        f"{path}:{name}": job
        for path in PUBLISH_WORKFLOWS
        for name, job in load(path)["jobs"].items()
    }


def test_publish_logic_is_loaded_from_the_workflow_revision() -> None:
    for name, job in all_publish_jobs().items():
        for step in job.get("steps", []):
            uses = step.get("uses", "")
            if uses.startswith("./.github/actions/"):
                assert uses in SOURCE_ACTIONS, (
                    f"{name} loads {uses} from the release source checkout; "
                    "check it out from github.workflow_sha into release-workflow "
                    "so retries of older tags use the current publish logic"
                )


def test_release_workflow_checkouts_use_the_workflow_revision() -> None:
    for name, job in all_publish_jobs().items():
        steps = job.get("steps", [])
        loaded = {
            step["uses"].removeprefix("./release-workflow/")
            for step in steps
            if step.get("uses", "").startswith("./release-workflow/")
        }
        if not loaded:
            continue
        checkouts = [
            step
            for step in steps
            if step.get("with", {}).get("path") == "release-workflow"
        ]
        assert len(checkouts) == 1, name
        checkout = checkouts[0]["with"]
        assert checkout["ref"] == WORKFLOW_SHA, name
        sparse = set(checkout.get("sparse-checkout", "").split())
        assert loaded <= sparse, f"{name} needs {loaded - sparse} in sparse-checkout"


def test_helm_charts_come_from_the_release_source() -> None:
    steps = publish_jobs()["release-helm"]["steps"]
    source = [
        step
        for step in steps
        if step.get("with", {}).get("ref") == SOURCE_SHA
        and "path" not in step.get("with", {})
    ]
    assert len(source) == 1
    assert steps.index(source[0]) < next(
        i
        for i, step in enumerate(steps)
        if step.get("uses") == "./release-workflow/.github/actions/release-helm-oci"
    )


def test_helm_action_keeps_published_public_charts() -> None:
    steps = load(".github/actions/release-helm-oci/action.yml")["runs"]["steps"]
    check = next(step for step in steps if step.get("id") == "published")
    assert check["if"] == "inputs.release-kind == 'public'"
    assert "Refuse duplicate" not in str(steps)
    skipped = "steps.published.outputs.published != 'true'"
    for name in ("Package Helm chart", "Push Helm chart to GHCR OCI"):
        step = next(step for step in steps if step.get("name") == name)
        assert step["if"] == skipped, name


def test_needed_jobs_skip_only_when_their_dependents_skip() -> None:
    # A skipped job fails the implicit success() check of every job after it,
    # so a needed job may only carry the same condition as each dependent.
    jobs = publish_jobs()
    for name, job in jobs.items():
        if job.get("if") == "always()":
            continue
        needs = job.get("needs", [])
        for need in [needs] if isinstance(needs, str) else needs:
            condition = jobs[need].get("if")
            if condition is not None:
                assert job.get("if") == condition, (
                    f"{name} needs {need}, which can be skipped by {condition!r}; "
                    "decide inside its steps instead"
                )


def test_publication_check_needs_every_publish_job() -> None:
    # The check fails the run when an expected publisher was skipped, so it
    # must see every other job in the graph.
    jobs = publish_jobs()
    check = jobs["check-publication"]
    assert check["if"] == "always()"
    assert set(check["needs"]) == set(jobs) - {"check-publication"}
