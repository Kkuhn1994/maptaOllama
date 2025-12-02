# Datei: function_tool.py
from functools import wraps
import inspect
import json
from typing import Any, Callable, Dict, Optional

def function_tool(
    func: Optional[Callable] = None,
    *,
    name_override: Optional[str] = None
) -> Callable:
    """
    Decorator für Tools, die im Agent-Loop verwendet werden.
    Extrahiert automatisch Name, Description und JSON-Schema.
    """
    def decorator(f: Callable) -> Callable:
        sig = inspect.signature(f)
        params = sig.parameters

        # JSON Schema für die Parameter erstellen
        properties = {}
        required = []

        for name, param in params.items():
            if param.default is param.empty:
                required.append(name)

            # Sehr einfache Typ-Erkennung
            if param.annotation is str:
                typ = "string"
            elif param.annotation is int:
                typ = "integer"
            elif param.annotation is bool:
                typ = "boolean"
            elif param.annotation is float:
                typ = "number"
            elif param.annotation is dict or param.annotation is Dict:
                typ = "object"
            elif param.annotation is list:
                typ = "array"
            elif param.annotation is Optional[str]:
                typ = "string"
            else:
                typ = "string"  # fallback

            properties[name] = {"type": typ}
            if param.default is not param.empty and param.default is not None:
                properties[name]["default"] = param.default
            if param.annotation is not param.empty and "description" in str(param.annotation):
                # falls du Typ-Hints mit Beschreibung hast, z.B. param: str = "Beschreibung"
                pass

        schema = {
            "type": "object",
            "properties": properties,
        }
        if required:
            schema["required"] = required

        # Docstring als Description
        description = inspect.getdoc(f) or ""

        # Name bestimmen
        tool_name = name_override or f.__name__

        @wraps(f)
        def wrapped(*args, **kwargs):
            return f(*args, **kwargs)

        wrapped.name = tool_name
        wrapped.description = description
        wrapped.params_json_schema = schema
        wrapped.strict_json_schema = True

        return wrapped

    if func is None:
        return decorator
    else:
        return decorator(func)
