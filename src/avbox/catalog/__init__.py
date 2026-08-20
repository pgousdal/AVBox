"""Catalog facade; declarative truth is implemented by :mod:`avbox.registry`."""

from avbox.registry import Registry, RegistryError, RegistryService

__all__ = ["Registry", "RegistryError", "RegistryService"]
