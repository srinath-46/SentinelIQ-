import logging
from typing import Dict, Any, Optional

from response.actions.base import ResponseAction

logger = logging.getLogger(__name__)

class ResponseExecutor:
    """
    Executes response actions. Manages the registry of available actions
    and handles manual (approval-gated) vs automated execution.
    """
    
    def __init__(self):
        self._actions: Dict[str, ResponseAction] = {}
        # In memory store for pending approvals. In production, this should be in PostgreSQL/Redis.
        self._pending_approvals: Dict[str, Dict[str, Any]] = {}

    def register_action(self, action: ResponseAction):
        self._actions[action.name] = action
        logger.info(f"Registered response action: {action.name}")

    async def trigger(self, action_name: str, target: str, context: Dict[str, Any]) -> bool:
        """
        Attempt to trigger an action. If it requires approval, queues it.
        Otherwise, executes it immediately.
        """
        action = self._actions.get(action_name)
        if not action:
            logger.error(f"Action '{action_name}' is not registered.")
            return False
            
        if not action.config.enabled:
            logger.warning(f"Action '{action_name}' is disabled.")
            return False
            
        if action.config.require_approval:
            # Queue for approval
            import uuid
            approval_id = str(uuid.uuid4())
            self._pending_approvals[approval_id] = {
                "action_name": action_name,
                "target": target,
                "context": context,
                "status": "pending"
            }
            logger.info(f"Action '{action_name}' against '{target}' requires approval. ID: {approval_id}")
            return True # Successfully queued
            
        # Execute immediately
        return await self._execute_action(action, target, context)

    async def approve_and_execute(self, approval_id: str, approver_user_id: str) -> bool:
        """
        Manually approve and execute a pending action.
        """
        pending = self._pending_approvals.get(approval_id)
        if not pending or pending["status"] != "pending":
            logger.error("Invalid or already processed approval ID.")
            return False
            
        action_name = pending["action_name"]
        target = pending["target"]
        context = pending["context"]
        
        action = self._actions.get(action_name)
        if not action:
            return False
            
        context["approved_by"] = approver_user_id
        success = await self._execute_action(action, target, context)
        
        pending["status"] = "executed" if success else "failed"
        return success

    async def _execute_action(self, action: ResponseAction, target: str, context: Dict[str, Any]) -> bool:
        try:
            return await action.execute(target, context)
        except Exception as e:
            logger.error(f"Execution failed for action {action.name}: {e}")
            return False
