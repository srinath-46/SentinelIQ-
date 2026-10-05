import logging
import sys
from pythonjsonlogger import jsonlogger
from typing import Any

def setup_logging(environment: str = "development") -> None:
    logger = logging.getLogger()
    
    # Remove default handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        
    handler = logging.StreamHandler(sys.stdout)
    
    if environment == "production":
        formatter = jsonlogger.JsonFormatter(
            '%(timestamp)s %(level)s %(name)s %(message)s %(request_id)s %(correlation_id)s',
            rename_fields={"levelname": "level", "asctime": "timestamp"}
        )
        logger.setLevel(logging.INFO)
    else:
        # Development friendly formatting
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(request_id)s] - %(message)s'
        )
        logger.setLevel(logging.DEBUG)
        
    handler.setFormatter(formatter)
    
    # Add custom filter to inject request_id and correlation_id
    class ContextFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            if not hasattr(record, 'request_id'):
                record.request_id = 'N/A'
            if not hasattr(record, 'correlation_id'):
                record.correlation_id = 'N/A'
            return True

    logger.addFilter(ContextFilter())
    logger.addHandler(handler)
