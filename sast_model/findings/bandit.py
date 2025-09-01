from typing_extensions import Annotated
from pydantic import BaseModel, Field, HttpUrl, field_validator, ValidationInfo
from typing import List, Optional


class IssueCWE(BaseModel):
    id: Annotated[int, Field(strict=True, gt=0)]
    link: HttpUrl


class BanditFinding(BaseModel):
    code: str
    col_offset: Annotated[int, Field(strict=True, ge=0)]
    end_col_offset: Annotated[int, Field(strict=True, gt=0)]
    filename: str
    issue_confidence: str
    issue_cwe: IssueCWE
    issue_severity: str
    issue_text: str
    line_number: Annotated[int, Field(strict=True, gt=0)]
    line_range: List[Annotated[int, Field(strict=True, gt=0)]]
    more_info: Optional[HttpUrl]
    test_id: str

    @field_validator("issue_confidence")
    def validate_confidence(cls, value, info: ValidationInfo):
        allowed_values = {"LOW", "MEDIUM", "HIGH"}
        if value not in allowed_values:
            raise ValueError(f"Issue confidence must be one of {allowed_values}")
        return value

    # Replace @validator with @field_validator for issue_severity
    @field_validator("issue_severity")
    def validate_severity(cls, value, info: ValidationInfo):
        allowed_values = {"LOW", "MEDIUM", "HIGH"}
        if value not in allowed_values:
            raise ValueError(f"Issue severity must be one of {allowed_values}")
        return value
