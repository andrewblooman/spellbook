"""The in-VPC agent worker.

A Cloud Run service (one per posture) that runs the validation agent with the
**Claude Agent SDK** and executes the bounded runner tools **in-process**. It
claims a dispatched run from the control plane, reasons over the finding, calls
the runner tools (each routed through the same server-side ``dispatch``/``decide``
enforcement the remote-MCP runner used), and posts the resulting ``Verdict`` back.

The agent brain and its "hands" are co-located inside the VPC; the model API is
the only egress. Posture / scope / authorizations are handed to the worker by the
control plane (server-authoritative) — the agent cannot widen its own scope.
"""
