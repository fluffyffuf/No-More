from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Plugin:
    name: str
    version: str = "0.1.0"
    description: str = ""
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


class PluginManager:
    """Registry for optional third-party NOMORE plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, Plugin] = {}

    def register(self, plugin: Plugin) -> None:
        self._plugins[plugin.name] = plugin

    def list(self) -> list[Plugin]:
        return sorted(self._plugins.values(), key=lambda item: item.name)

    def get(self, name: str) -> Plugin | None:
        return self._plugins.get(name)

    def install(self, plugin_name: str, plugin: Plugin | None = None) -> Plugin:
        target = plugin or Plugin(name=plugin_name)
        self.register(target)
        return target
