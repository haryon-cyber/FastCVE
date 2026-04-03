from datetime import datetime
from typing import List, Optional, Any
from pydantic import BaseModel


class CveChangeDetail(BaseModel):
    class Config:
        extra = 'allow'  # details are not fully stable

    type: Optional[str] = None
    oldValue: Optional[Any] = None
    newValue: Optional[Any] = None



class CveHistoryItem(BaseModel):
    class Config:
        extra = 'ignore'

    cveId: str
    cveChangeId: str
    eventName: str
    sourceIdentifier: Optional[str] = None
    created: datetime
    details: Optional[List[CveChangeDetail]] = None
