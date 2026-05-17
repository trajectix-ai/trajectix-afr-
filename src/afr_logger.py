import json
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path


class AFRLogger:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.step_counter = 0
        self.prev_event_hash = "GENESIS"

        base_dir = Path(__file__).parent.parent
        self.output_path = base_dir / "output" / f"{session_id}.jsonl"
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.touch()

    def log_step(self, step_type: str, content: str, metadata: dict = None) -> dict:
        self.step_counter += 1

        metadata = metadata or {}
        action_classification = metadata.get("action_classification", "BENIGN")
        human_approval_obtained = metadata.get("human_approval_obtained", False)

        event = {
            "event_id": str(uuid.uuid4()),
            "trajectory_id": self.session_id,
            "step_number": self.step_counter,
            "step_type": step_type,
            "content": content,
            "metadata": metadata,
            "action_classification": action_classification,
            "human_approval_obtained": human_approval_obtained,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "prev_event_hash": self.prev_event_hash,
        }

        event_hash = hashlib.sha256(
            json.dumps(event, sort_keys=True).encode()
        ).hexdigest()
        event["event_hash"] = event_hash

        with self.output_path.open("a") as f:
            f.write(json.dumps(event) + "\n")

        self.prev_event_hash = event_hash
        return event

    def verify_chain(self) -> bool:
        events = []
        with self.output_path.open("r") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))

        expected_prev = "GENESIS"
        for event in events:
            stored_hash = event.pop("event_hash")

            if event.get("prev_event_hash") != expected_prev:
                return False

            recomputed = hashlib.sha256(
                json.dumps(event, sort_keys=True).encode()
            ).hexdigest()

            if recomputed != stored_hash:
                return False

            event["event_hash"] = stored_hash
            expected_prev = stored_hash

        return True

    def get_session_path(self) -> Path:
        return self.output_path


if __name__ == "__main__":
    logger = AFRLogger("test-session-001")

    logger.log_step("OBSERVATION", "Agent received task: analyse sales data")
    logger.log_step("TOOL_CALL", "read_file('sales_q1.csv')", metadata={"tool": "read_file"})
    logger.log_step(
        "TOOL_CALL",
        "execute_query('DROP TABLE sales')",
        metadata={"action_classification": "DESTRUCTIVE", "tool": "sql_exec"},
    )

    valid = logger.verify_chain()
    print(f"Chain valid: {valid}")
    print(f"Log written to: {logger.get_session_path()}")
