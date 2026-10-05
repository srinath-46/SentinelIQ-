import logging
from typing import Dict, Any, List

from response.executor import ResponseExecutor
from response.playbooks.definitions import Playbook, DEFAULT_PLAYBOOKS

logger = logging.getLogger(__name__)

class PlaybookEngine:
    """
    Evaluates events against defined playbooks and triggers automated response actions.
    """
    
    def __init__(self, executor: ResponseExecutor):
        self.executor = executor
        self.playbooks: List[Playbook] = DEFAULT_PLAYBOOKS.copy()

    def add_playbook(self, playbook: Playbook):
        self.playbooks.append(playbook)

    def _evaluate_condition(self, condition, event: Dict[str, Any]) -> bool:
        # Simple dot-notation field extractor
        parts = condition.field.split(".")
        val = event
        for p in parts:
            if isinstance(val, dict):
                val = val.get(p)
            else:
                val = None
                
        if val is None:
            return False
            
        if condition.operator == "eq":
            return val == condition.value
        elif condition.operator == "contains":
            return condition.value in str(val)
        elif condition.operator == "gt":
            try:
                if not isinstance(val, (int, float, str)):
                    return False
                return float(val) > float(condition.value)
            except (ValueError, TypeError):
                return False
        return False

    async def evaluate_event(self, event: Dict[str, Any]):
        """
        Evaluate a high severity or alerted event against all enabled playbooks.
        """
        for pb in self.playbooks:
            if not pb.enabled:
                continue
                
            # Check if all conditions match (AND logic)
            matches = all(self._evaluate_condition(cond, event) for cond in pb.conditions)
            
            if matches:
                logger.info(f"Event {event.get('event_id')} matched playbook: {pb.name}")
                await self._execute_playbook(pb, event)

    async def _execute_playbook(self, playbook: Playbook, event: Dict[str, Any]):
        """Trigger all actions defined in the matched playbook."""
        for action_def in playbook.actions:
            # Extract target from the event
            target = event.get(action_def.target_field)
            if not target:
                logger.warning(f"Could not extract target field '{action_def.target_field}' for action '{action_def.action_name}'")
                continue
                
            # Configure context for the executor
            context = {
                "event_id": event.get("event_id"),
                "playbook_id": playbook.id,
                "reason": f"Matched Playbook: {playbook.name}"
            }
            
            # The executor naturally handles require_approval gating based on the Action's config,
            # but we can also override or enforce playbook-level approval here if needed.
            await self.executor.trigger(
                action_name=action_def.action_name,
                target=target,
                context=context
            )
