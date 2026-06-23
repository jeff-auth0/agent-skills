from auth0tf.hclgen import render_value, render_type


def test_render_string():
    assert render_value("hello") == '"hello"'


def test_render_bool_and_number():
    assert render_value(True) == "true"
    assert render_value(3) == "3"


def test_render_ref_unquoted():
    assert render_value({"__ref__": "var.x"}) == "var.x"


def test_render_list():
    assert render_value(["a", "b"]) == '["a", "b"]'


def test_render_object():
    # keys are left-justified to the longest key width; one space before '='.
    out = render_value({"name": "A", "app_type": "spa"})
    assert out == '{\n  name     = "A"\n  app_type = "spa"\n}'


def test_render_type_scalars():
    assert render_type("hello") == "string"
    assert render_type(True) == "bool"
    assert render_type(3) == "number"


def test_render_type_object():
    t = render_type({"name": "A", "n": 1})
    assert t == "object({\n    name = string\n    n    = number\n  })"
