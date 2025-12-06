# src/model_signing/model_card.py
from typing import List, Optional, Union, Any
from pydantic import BaseModel, Field, ConfigDict

class ModelCardMetadata(BaseModel):
    """
    Strict schema for Model Card Metadata based on Hugging Face specs 
    and the user-provided template.
    """
    model_config = ConfigDict(extra='allow') # Allow extra fields (HF custom tags), set to 'forbid' for strict strictness.

    # --- Standard HF Hub Metadata ---
    language: Optional[Union[str, List[str]]] = None
    license: Optional[str] = None
    library_name: Optional[str] = None
    tags: Optional[List[str]] = Field(default_factory=list)
    datasets: Optional[List[str]] = Field(default_factory=list)
    metrics: Optional[List[str]] = Field(default_factory=list)
    pipeline_tag: Optional[str] = None
    
    # --- Template Specific Fields ---
    model_id: Optional[str] = None
    model_summary: Optional[str] = None
    model_description: Optional[str] = None
    
    developers: Optional[Union[str, List[str]]] = None
    funded_by: Optional[Union[str, List[str]]] = None
    shared_by: Optional[Union[str, List[str]]] = None
    
    model_type: Optional[str] = None
    finetuned_from: Optional[str] = Field(alias="base_model", default=None)
    
    repo: Optional[str] = None
    paper: Optional[str] = None
    demo: Optional[str] = None
    
    # --- Usage & Risks ---
    direct_use: Optional[str] = None
    downstream_use: Optional[str] = None
    out_of_scope_use: Optional[str] = None
    bias_risks_limitations: Optional[str] = None
    bias_recommendations: Optional[str] = None
    
    # --- Training & Eval ---
    training_data: Optional[str] = None
    training_regime: Optional[str] = None
    preprocessing: Optional[str] = None
    
    testing_data: Optional[str] = None
    testing_factors: Optional[str] = None
    testing_metrics: Optional[str] = None
    results: Optional[str] = None
    
    # --- Carbon Footprint ---
    hardware_type: Optional[str] = None
    hours_used: Optional[Union[int, float]] = None
    cloud_provider: Optional[str] = None
    cloud_region: Optional[str] = None
    co2_emitted: Optional[Union[int, float]] = None

    # --- Citation ---
    citation_bibtex: Optional[str] = None
    citation_apa: Optional[str] = None