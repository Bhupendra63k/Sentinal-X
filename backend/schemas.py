from pydantic import BaseModel,field_validator
from backend.target_validation import validate_target

class ScanRequest(BaseModel):
    scanner:str
    scan_type:str
    target:str

    @field_validator("scanner","scan_type","target")
    @classmethod
    def reject_empty_values(cls,value):
        value =value.strip()
        if not value:
            raise ValueError("This field cannot be empty")
        return value

    @field_validator("target")
    @classmethod
    def validate_target_format(cls,value):
        return validate_target(value)
    
class FullScanRequest(BaseModel):
    target:str

    @field_validator("target")
    @classmethod
    def reject_empty_target(cls,value):
        value=value.strip()
        if not value:
            raise ValueError("Target cannot be empty")
        return value

    @field_validator("target")
    @classmethod
    def validate_target_format(cls,value):
        return validate_target(value)

class CredentialScanRequest(BaseModel):
    scan_type:str
    target:str
    hash_file:str | None=None
    wordlist:str | None=None
    mode:str | None= None
    @field_validator("scan_type","target")
    @classmethod
    def reject_empty_values(cls,value):
        value=value.strip()
        if not value:
            raise ValueError("This field cannot be empty")
        return value

    @field_validator("target")
    @classmethod
    def validate_target_format(cls,value):
        return validate_target(value)

    @field_validator("hash_file","wordlist")
    @classmethod
    def reject_blank_optional_paths(cls,value):
        if value is not None:
            value=value.strip()
            if not value:
                return None
            return value

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, value):
        if value is not None:
            value=value.strip()
            if not value:
                raise ValueError("Mode cannot be empty")
            if not value.isdigit():
                raise ValueError("Mode must be a numeric string")
        return value


