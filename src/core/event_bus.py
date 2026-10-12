"""
Event Bus for asynchronous messaging between components (capture, detectors, defense, alerts).
"""
import asyncio
from collections import defaultdict
from typing import Callable, Any, Dict, List
from datetime import datetime, timezone

class Event:
    def __init__(self, event_type: str, data: Dict[str, Any], timestamp: datetime = None):
        self.event_type = event_type
        self.data = data
        self.timestamp = timestamp or datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "data": self.data,
            "timestamp": self.timestamp.isoformat()
        }

class EventBus:
    def __init__(self):
        self._subscribers: Dict[str, List[Callable[[Event], Any]]] = defaultdict(list)
        self._history: List[Event] = []
        self._max_history = 1000

    def subscribe(self, event_type: str, handler: Callable[[Event], Any]):
        """Subscribe a callable handler to a specific event type or '*' for all."""
        self._subscribers[event_type].append(handler)

    def publish(self, event_type: str, data: Dict[str, Any]) -> Event:
        """Publish an event to all subscribed listeners synchronously or via callback."""
        event = Event(event_type, data)
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history.pop(0)

        # Notify exact matches
        for handler in self._subscribers.get(event_type, []):
            try:
                handler(event)
            except Exception as e:
                print(f"[EventBus] Error in handler {handler.__name__}: {e}")

        # Notify wildcard listeners
        for handler in self._subscribers.get("*", []):
            try:
                handler(event)
            except Exception as e:
                print(f"[EventBus] Error in wildcard handler {handler.__name__}: {e}")

        return event

    def get_history(self, limit: int = 50, event_type: str = None) -> List[Dict[str, Any]]:
        events = self._history
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return [e.to_dict() for e in events[-limit:]]
