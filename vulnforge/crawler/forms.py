"""HTML Form parser and parameter discovery."""

from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from vulnforge.models.parameter import Parameter, ParameterLocation
from vulnforge.utils.normalization import normalize_url


@dataclass
class FormField:
    """Represents an input field inside an HTML form."""

    name: str
    field_type: str  # text, password, hidden, email, select, textarea, checkbox, etc.
    value: Optional[str] = None
    required: bool = False
    options: List[str] = field(default_factory=list)


@dataclass
class DiscoveredForm:
    """Represents a discovered HTML form."""

    action: str
    method: str  # GET or POST
    enctype: str
    fields: List[FormField] = field(default_factory=list)
    source_url: str = ""
    form_name: Optional[str] = None
    form_id: Optional[str] = None

    def to_parameters(self) -> List[Parameter]:
        """Convert form fields into Parameter model objects."""
        loc = ParameterLocation.FORM if self.method == "POST" else ParameterLocation.QUERY
        parameters: List[Parameter] = []
        for f in self.fields:
            if not f.name:
                continue
            parameters.append(
                Parameter(
                    name=f.name,
                    location=loc,
                    param_type=f.field_type,
                    sample_value=f.value,
                    endpoint_url=self.action,
                    source="FORM",
                )
            )
        return parameters


def extract_forms_from_html(html_content: str, base_url: str) -> List[DiscoveredForm]:
    """Parse HTML and extract all form elements, actions, methods, and input fields.

    Args:
        html_content: Raw HTML text body.
        base_url: Current page URL to resolve relative form actions.

    Returns:
        List of DiscoveredForm objects.
    """
    if not html_content or not isinstance(html_content, str):
        return []

    try:
        soup = BeautifulSoup(html_content, "html.parser")
    except Exception:
        return []

    forms: List[DiscoveredForm] = []

    for form_tag in soup.find_all("form"):
        # Resolve action
        raw_action = form_tag.get("action", "")
        if raw_action:
            action_url = normalize_url(urljoin(base_url, raw_action))
        else:
            action_url = normalize_url(base_url)

        method = form_tag.get("method", "GET").upper()
        if method not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
            method = "GET"

        enctype = form_tag.get("enctype", "application/x-www-form-urlencoded")
        form_name = form_tag.get("name")
        form_id = form_tag.get("id")

        fields: List[FormField] = []

        # 1. <input> elements
        for inp in form_tag.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            inp_type = inp.get("type", "text").lower()
            val = inp.get("value")
            req = inp.has_attr("required")
            fields.append(
                FormField(
                    name=name,
                    field_type=inp_type,
                    value=val,
                    required=req,
                )
            )

        # 2. <textarea> elements
        for ta in form_tag.find_all("textarea"):
            name = ta.get("name")
            if not name:
                continue
            val = ta.string.strip() if ta.string else None
            req = ta.has_attr("required")
            fields.append(
                FormField(
                    name=name,
                    field_type="textarea",
                    value=val,
                    required=req,
                )
            )

        # 3. <select> elements
        for sel in form_tag.find_all("select"):
            name = sel.get("name")
            if not name:
                continue
            opts: List[str] = []
            selected_val = None
            for opt in sel.find_all("option"):
                opt_val = opt.get("value", opt.text.strip())
                opts.append(opt_val)
                if opt.has_attr("selected"):
                    selected_val = opt_val

            if not selected_val and opts:
                selected_val = opts[0]

            fields.append(
                FormField(
                    name=name,
                    field_type="select",
                    value=selected_val,
                    required=sel.has_attr("required"),
                    options=opts,
                )
            )

        forms.append(
            DiscoveredForm(
                action=action_url,
                method=method,
                enctype=enctype,
                fields=fields,
                source_url=base_url,
                form_name=form_name,
                form_id=form_id,
            )
        )

    return forms
