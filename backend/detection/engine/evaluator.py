import re
from typing import Any, Dict, List, Optional

class RuleEvaluator:
    """Evaluates a detection rule's conditions against a single event."""
    
    @staticmethod
    def _get_field_value(event: Dict[str, Any], field_path: str) -> Any:
        """Extract a value from a nested dict using dot notation."""
        keys = field_path.split('.')
        val = event
        for key in keys:
            if isinstance(val, dict) and key in val:
                val = val[key]
            else:
                return None
        return val

    @staticmethod
    def _evaluate_single_condition(event: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        field = condition.get("field")
        op = condition.get("operator")
        expected = condition.get("value")
        
        if not field or not op:
            return False
            
        actual = RuleEvaluator._get_field_value(event, field)
        
        if op == "exists":
            return actual is not None
        if op == "not_exists":
            return actual is None
            
        if actual is None:
            return False
            
        if op == "equals":
            return actual == expected
        if op == "not_equals":
            return actual != expected
        if op == "in":
            return isinstance(expected, list) and actual in expected
        if op == "not_in":
            return isinstance(expected, list) and actual not in expected
        if op == "contains":
            return isinstance(actual, (str, list, dict)) and expected in actual
        if op == "starts_with":
            return isinstance(actual, str) and actual.startswith(str(expected))
        if op == "ends_with":
            return isinstance(actual, str) and actual.endswith(str(expected))
        if op == "greater_than":
            try: return float(actual) > float(expected)
            except: return False
        if op == "greater_than_or_equal":
            try: return float(actual) >= float(expected)
            except: return False
        if op == "less_than":
            try: return float(actual) < float(expected)
            except: return False
        if op == "less_than_or_equal":
            try: return float(actual) <= float(expected)
            except: return False
        if op == "regex":
            if not isinstance(actual, str): return False
            try: return bool(re.search(str(expected), actual))
            except: return False
            
        return False

    @staticmethod
    def evaluate(event: Dict[str, Any], condition_block: Dict[str, Any]) -> bool:
        """
        Recursively evaluate a block of conditions.
        Format: {"operator": "AND", "conditions": [...]}
        """
        operator = condition_block.get("operator", "AND").upper()
        conditions = condition_block.get("conditions", [])
        
        if not conditions:
            return False
            
        if operator == "AND":
            for cond in conditions:
                if "operator" in cond and "conditions" in cond:
                    if not RuleEvaluator.evaluate(event, cond):
                        return False
                else:
                    if not RuleEvaluator._evaluate_single_condition(event, cond):
                        return False
            return True
            
        elif operator == "OR":
            for cond in conditions:
                if "operator" in cond and "conditions" in cond:
                    if RuleEvaluator.evaluate(event, cond):
                        return True
                else:
                    if RuleEvaluator._evaluate_single_condition(event, cond):
                        return True
            return False
            
        elif operator == "NOT":
            # For NOT, typically we expect 1 condition, but we'll assume it applies to the first
            if not conditions: return True
            cond = conditions[0]
            if "operator" in cond and "conditions" in cond:
                return not RuleEvaluator.evaluate(event, cond)
            else:
                return not RuleEvaluator._evaluate_single_condition(event, cond)
                
        return False
