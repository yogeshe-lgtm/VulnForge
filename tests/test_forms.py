"""Tests for HTML form extraction and parameter parsing."""

from vulnforge.crawler.forms import extract_forms_from_html
from vulnforge.models.parameter import ParameterLocation


def test_extract_get_form_with_inputs():
    """Verify extracting GET form and query parameters."""
    html = """
    <html>
        <body>
            <form action="/search" method="GET" id="search-form">
                <input type="text" name="q" value="default-query" required />
                <input type="hidden" name="category" value="security" />
                <select name="sort">
                    <option value="relevance">Relevance</option>
                    <option value="date" selected>Date</option>
                </select>
                <textarea name="notes">Search comments</textarea>
                <input type="submit" value="Search" />
            </form>
        </body>
    </html>
    """
    forms = extract_forms_from_html(html, "https://example.com/home")

    assert len(forms) == 1
    form = forms[0]
    assert form.action == "https://example.com/search"
    assert form.method == "GET"
    assert form.form_id == "search-form"
    assert len(form.fields) == 4

    # Convert to parameters
    params = form.to_parameters()
    assert len(params) == 4
    param_dict = {p.name: p for p in params}

    assert "q" in param_dict
    assert param_dict["q"].location == ParameterLocation.QUERY
    assert param_dict["q"].sample_value == "default-query"
    assert param_dict["q"].param_type == "text"

    assert "category" in param_dict
    assert param_dict["category"].param_type == "hidden"
    assert param_dict["category"].sample_value == "security"

    assert "sort" in param_dict
    assert param_dict["sort"].sample_value == "date"

    assert "notes" in param_dict
    assert param_dict["notes"].param_type == "textarea"


def test_extract_post_form_with_action():
    """Verify extracting POST form and form body parameters."""
    html = """
    <form action="https://api.example.com/v1/login" method="POST">
        <input type="email" name="email" required />
        <input type="password" name="password" required />
    </form>
    """
    forms = extract_forms_from_html(html, "https://example.com")
    assert len(forms) == 1
    form = forms[0]
    assert form.action == "https://api.example.com/v1/login"
    assert form.method == "POST"

    params = form.to_parameters()
    assert len(params) == 2
    for p in params:
        assert p.location == ParameterLocation.FORM


def test_form_relative_action_resolution():
    """Verify relative form action resolves against base URL."""
    html = '<form action="submit.php"><input name="test" /></form>'
    forms = extract_forms_from_html(html, "https://example.com/app/index.html")
    assert len(forms) == 1
    assert forms[0].action == "https://example.com/app/submit.php"
