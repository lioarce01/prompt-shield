"""
Base Pydantic model with optimized configuration for the application
"""
from pydantic import BaseModel as PydanticBaseModel


class BaseModel(PydanticBaseModel):
    """Enhanced BaseModel with application-specific configuration"""
    
    model_config = {
        "from_attributes": True,
        "protected_namespaces": (),
        "validate_assignment": True,
        "use_enum_values": True
    }