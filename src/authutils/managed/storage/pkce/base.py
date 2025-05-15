from abc import ABC, abstractmethod
from ....common.types.constants import ProviderTypeEnum

class PKCEStorage(ABC):
    @abstractmethod
    def store(self, state: str, code_verifier: str, provider: ProviderTypeEnum):
        pass

    @abstractmethod
    def retrieve_and_clear(self, state: str) -> tuple[str, ProviderTypeEnum] | None:
        pass