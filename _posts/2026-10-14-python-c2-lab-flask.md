---
title: "Building a Simple Command-and-Control (C2) Lab with Python and Flask"
date: 2026-10-13 00:00:00 +0800
categories: [Red Teaming, Tools]
tags: [c2, python, flask, requests, http, command-and-control]
---

Command-and-control (C2) is a core concept in red teaming and adversary simulation. It describes the communication channel through which an operator interacts with an agent running on a system.

In this post, we'll model the basic mechanics with Python, Flask, and Requests: an agent periodically checks in, a server hands out queued tasks, and the agent sends results back.

> **Lab scope:** This walkthrough is designed for a local, controlled lab. The agent supports only a small allowlist of read-only diagnostic tasks; it does not execute arbitrary shell commands. Do not expose the development server to untrusted networks.

## 1. Architecture

A simple polling-based design has three logical components:

- **C2 server:** Receives check-ins and distributes queued tasks.
- **Agent:** Periodically contacts the server and runs an approved task.
- **Operator:** Queues tasks and reviews the results.

The flow is:

1. The agent sends a beacon containing its identifier.
2. The server checks whether a task is queued for that agent.
3. The server returns a task or `null` if the queue is empty.
4. The agent runs the corresponding approved diagnostic function.
5. The agent posts the result back to the server.
6. The agent sleeps briefly before polling again.

HTTP is convenient for this demonstration because both Python libraries and local debugging tools support it. HTTP by itself does not make traffic stealthy; network controls, proxies, and monitoring may observe or block it.

## 2. Prerequisites

Use Python 3. Create a directory and virtual environment:

```bash
mkdir python-c2-lab
cd python-c2-lab
python -m venv .venv
```

Activate it on Linux or macOS:

```bash
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the dependencies:

```bash
pip install flask requests cryptography
```

What each package does:

| Package | Purpose |
| --- | --- |
| Flask | Provides the HTTP server and API routes |
| Requests | Sends HTTP requests from the agent |
| cryptography | Offers cryptographic primitives for applications that need them |

The sample code uses Flask and Requests only. It does not import `cryptography`, so you can omit that package for this specific lab. Installing a cryptography library does not automatically encrypt HTTP traffic or provide authentication.

## 3. Build the server

Create `server.py`:

```python
from collections import defaultdict, deque
from flask import Flask, request, jsonify

app = Flask(__name__)

# In-memory task queues and result storage.
tasks = defaultdict(deque)
results = defaultdict(list)


@app.route("/beacon", methods=["POST"])
def beacon():
    data = request.get_json(silent=True) or {}
    agent_id = data.get("id")

    if not isinstance(agent_id, str) or not agent_id:
        return jsonify({"error": "Invalid agent ID"}), 400

    if tasks[agent_id]:
        task = tasks[agent_id].popleft()
        return jsonify({"task": task})

    return jsonify({"task": None})


@app.route("/result", methods=["POST"])
def result():
    data = request.get_json(silent=True) or {}
    agent_id = data.get("id")
    task_name = data.get("task")
    output = data.get("output")

    if (
        not isinstance(agent_id, str)
        or not isinstance(task_name, str)
        or not isinstance(output, str)
    ):
        return jsonify({"error": "Invalid result"}), 400

    record = {"task": task_name, "output": output}
    results[agent_id].append(record)

    print(f"[+] Result from {agent_id}")
    print(f"Task: {task_name}")
    print(output)

    return jsonify({"status": "received"})


@app.route("/queue", methods=["POST"])
def queue_task():
    data = request.get_json(silent=True) or {}
    agent_id = data.get("id")
    task_name = data.get("task")

    allowed_tasks = {"hostname", "platform", "time"}

    if not isinstance(agent_id, str) or not agent_id:
        return jsonify({"error": "Invalid agent ID"}), 400

    if task_name not in allowed_tasks:
        return jsonify({"error": "Task not allowed"}), 400

    tasks[agent_id].append(task_name)

    return jsonify({
        "status": "queued",
        "id": agent_id,
        "task": task_name,
    })


if __name__ == "__main__":
    # Keep the lab bound to loopback.
    app.run(host="127.0.0.1", port=5000, debug=False)
```

### How the server works

**Application and state**

`Flask(__name__)` creates the application. The `tasks` dictionary maps each agent ID to a FIFO queue. `results` stores returned task records in memory.

Because this state is not persisted, restarting the server clears queued tasks and results. This is fine for a short demonstration, but not suitable for durable operations.

**`POST /beacon`**

The agent sends its ID to this endpoint. If a task is waiting, `popleft()` removes the oldest task and returns it. Otherwise, the server responds with:

```json
{"task": null}
```

**`POST /queue`**

This endpoint queues a named task for an agent. The server accepts only `hostname`, `platform`, and `time`; arbitrary command strings are rejected.

**`POST /result`**

The agent submits its ID, task name, and output. The server stores the record and prints it to the terminal. The task name is stored alongside the output so that results can be correlated with the operation that produced them.

The allowlist is not authentication. Anyone who can reach an unauthenticated queue endpoint could still request allowed tasks. The local-only binding limits network exposure, but does not authenticate local users or processes.

## 4. Build the agent

Create `agent.py`:

```python
import platform
import socket
import time
from datetime import datetime, timezone

import requests

SERVER_URL = "http://127.0.0.1:5000"
AGENT_ID = "agent_01"
POLL_INTERVAL = 5

session = requests.Session()


def run_task(task_name):
    """Run one predefined, read-only diagnostic task."""

    if task_name == "hostname":
        return socket.gethostname()

    if task_name == "platform":
        return platform.platform()

    if task_name == "time":
        return datetime.now(timezone.utc).isoformat()

    return "Unsupported task"


def run_agent():
    while True:
        try:
            response = session.post(
                f"{SERVER_URL}/beacon",
                json={"id": AGENT_ID},
                timeout=5,
            )
            response.raise_for_status()

            data = response.json()
            task_name = data.get("task")

            if task_name:
                output = run_task(task_name)

                result_response = session.post(
                    f"{SERVER_URL}/result",
                    json={
                        "id": AGENT_ID,
                        "task": task_name,
                        "output": output,
                    },
                    timeout=5,
                )
                result_response.raise_for_status()

                print(f"[+] Completed task: {task_name}")

        except requests.RequestException as exc:
            print(f"[!] Communication error: {exc}")

        except ValueError as exc:
            print(f"[!] Invalid server response: {exc}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run_agent()
```

### How the agent works

- **Configuration:** `SERVER_URL` sets the server address, `AGENT_ID` identifies the instance, and `POLL_INTERVAL` controls the delay between check-ins.
- **HTTP session:** `requests.Session()` can reuse connection settings and HTTP connections where possible.
- **Task dispatcher:** `run_task()` maps known task names to fixed Python functions. The received value is never passed to a shell.
- **Beacon loop:** The agent requests a task, processes the response, reports a result when a task exists, and sleeps before polling again.
- **Timeouts and errors:** Request timeouts prevent a network operation from waiting indefinitely. Exceptions are reported rather than silently swallowed.

The server and agent both enforce the task allowlist. That is intentional: server-side validation controls what can be queued, while the agent-side dispatcher limits what it will actually run.

## 5. Run the lab

Open two terminals in the project directory and activate the virtual environment in each.

In terminal one, start the server:

```bash
python server.py
```

It should listen on `http://127.0.0.1:5000`. In terminal two, start the agent:

```bash
python agent.py
```

The agent begins polling every five seconds. With an empty queue, it stays idle.

## 6. Sample usage

Use a third terminal to queue a task with `curl`.

### Queue a hostname task

```bash
curl -X POST http://127.0.0.1:5000/queue \
  -H "Content-Type: application/json" \
  -d '{"id":"agent_01","task":"hostname"}'
```

The response should resemble the following illustrative JSON:

```json
{
  "status": "queued",
  "id": "agent_01",
  "task": "hostname"
}
```

The task is queued until the agent next polls. The agent then calls `socket.gethostname()` and submits the result.

### Queue a platform task

```bash
curl -X POST http://127.0.0.1:5000/queue \
  -H "Content-Type: application/json" \
  -d '{"id":"agent_01","task":"platform"}'
```

This returns a platform description generated by Python. Its exact value depends on the operating system.

### Queue a UTC time task

```bash
curl -X POST http://127.0.0.1:5000/queue \
  -H "Content-Type: application/json" \
  -d '{"id":"agent_01","task":"time"}'
```

The agent returns a UTC timestamp in ISO 8601 format.

### Try an unsupported task

```bash
curl -X POST http://127.0.0.1:5000/queue \
  -H "Content-Type: application/json" \
  -d '{"id":"agent_01","task":"whoami"}'
```

The server rejects this request with HTTP status `400` and a response similar to:

```json
{"error": "Task not allowed"}
```

These are expected responses based on the code, not captured results from an executed lab.

### Observe the result

When a task completes, the server prints a record with the agent ID, task name, and returned output. For a hostname task, the output will be the hostname of the machine running the agent. The agent also prints a completion message.

## 7. What this lab does—and does not—provide

| Feature | This lab | Production consideration |
| --- | --- | --- |
| Agent identity | Static ID | Enrollment and authenticated identity |
| Communication | HTTP polling | TLS and explicit network policy |
| Task execution | Fixed allowlist | Authorization and tightly constrained task types |
| Task queue | In-memory | Durable storage and task state |
| Results | In-memory and console | Persistence, access control, retention |
| Reliability | Basic timeout handling | Retry policy, backoff, and monitoring |
| Security | Localhost-only | Authentication, validation, audit logs |

This is a small educational model, not a full C2 platform. It has no persistent storage, enrollment workflow, authentication, operator UI, or production-grade concurrency handling.

## 8. Troubleshooting

**Connection refused:** Make sure the server is running on port `5000` and that `SERVER_URL` matches it.

**The task never runs:** The agent ID in the queue request must exactly match `AGENT_ID`. The agent polls every five seconds, so a brief delay is normal.

**The server rejects a task:** Only `hostname`, `platform`, and `time` are accepted. Names are case-sensitive.

**Invalid JSON or request errors:** Check the `Content-Type: application/json` header and ensure the request body is valid JSON. Review the HTTP response and agent diagnostic messages.

**Why is `cryptography` unused?** The code does not import it. A cryptographic library does not automatically encrypt HTTP traffic or authenticate clients.

## 9. Security and detection notes

Even a small tasking system needs careful boundaries:

- **Authentication and authorization:** Protect task submission and restrict who can request operations.
- **Transport security:** Use correctly configured TLS for communication across a network.
- **Execution controls:** Do not interpret remotely supplied strings as shell input. Prefer predefined operations and validate their inputs.
- **Auditability:** Log task IDs, timestamps, outcomes, and errors without recording secrets.
- **Deployment:** Do not expose Flask's development server to untrusted networks.

For defensive testing, this design also illustrates observable behaviors: periodic outbound requests, repeated API endpoint access, task/result exchanges, and network activity associated with a Python process. These can be used to build lab detections and validate monitoring.

## 10. Conclusion

The core mechanics of a polling-based C2 design can be broken down into beaconing, task delivery, and result reporting. Flask provides the server endpoints, Requests handles HTTP communication, and a dispatcher defines which operations are allowed.

The allowlisted version here keeps the demonstration local and avoids turning remotely supplied data into arbitrary shell commands. Useful next steps for a controlled lab include adding authenticated task submission, persistent task storage, structured audit logs, and unit tests.

## References

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Requests Documentation](https://requests.readthedocs.io/)
- [Python `socket` Documentation](https://docs.python.org/3/library/socket.html)
- [Python `platform` Documentation](https://docs.python.org/3/library/platform.html)
- [MITRE ATT&CK: Command and Control (TA0011)](https://attack.mitre.org/tactics/TA0011/)
- [Python Cryptography Documentation](https://cryptography.io/en/latest/)
