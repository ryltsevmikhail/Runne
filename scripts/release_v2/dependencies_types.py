from dataclasses import dataclass


@dataclass(frozen=True)
class DependencyPackageV1:
    ecosystem: str
    name: str
    version: str
    lock_locator: str
    source_digest: str
    declared_license: str | None
    dependencies: tuple[str, ...]
    direct: bool

    @property
    def reference(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


@dataclass(frozen=True)
class DependencyInventoryV1:
    packages: tuple[DependencyPackageV1, ...]
    inventory_sha256: str
