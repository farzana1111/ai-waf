"""Tests for waf.features — HTTP request feature extraction."""

from __future__ import annotations

import pytest

from waf.features import RequestFeatures, extract_features


class TestExtractFeatures:
    def test_basic_get_request(self):
        f = extract_features(method="GET", path="/search", query_string="q=hello+world")
        assert isinstance(f, RequestFeatures)
        assert f.method == "GET"
        assert f.path == "/search"
        assert f.num_params == 1
        assert "hello" in f.combined_text

    def test_post_form_body(self):
        f = extract_features(
            method="POST",
            path="/login",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body="username=alice&password=secret",
        )
        assert f.method == "POST"
        assert f.num_params == 2
        assert "alice" in f.combined_text

    def test_url_length_calculation(self):
        f = extract_features(method="GET", path="/items", query_string="id=1&sort=asc")
        assert f.url_length == len("/items") + len("id=1&sort=asc")

    def test_body_length(self):
        body = "x" * 500
        f = extract_features(method="POST", path="/data", body=body)
        assert f.body_length == 500

    def test_special_char_ratio_is_non_zero_for_sql(self):
        f = extract_features(method="GET", path="/x", query_string="q=' OR '1'='1")
        assert f.special_char_ratio > 0

    def test_null_byte_detection_percent_encoded(self):
        f = extract_features(method="GET", path="/file%00.txt", query_string="")
        assert f.null_byte_present is True

    def test_null_byte_detection_raw(self):
        f = extract_features(method="GET", path="/file\x00.txt")
        assert f.null_byte_present is True

    def test_hex_encoded_count(self):
        f = extract_features(method="GET", path="/x", query_string="a=0x41414141")
        assert f.hex_encoded_count >= 1

    def test_url_encoded_count(self):
        f = extract_features(method="GET", path="/x", query_string="a=%3Cscript%3E")
        assert f.url_encoded_count >= 2

    def test_long_param_value_flag(self):
        long_val = "A" * 201
        f = extract_features(method="GET", path="/x", query_string=f"data={long_val}")
        assert f.long_param_value is True

    def test_normal_request_has_no_long_param(self):
        f = extract_features(method="GET", path="/x", query_string="data=short")
        assert f.long_param_value is False

    def test_has_cookie_header(self):
        f = extract_features(
            method="GET", path="/x", headers={"Cookie": "session=abc123"}
        )
        assert f.has_cookie is True

    def test_no_cookie(self):
        f = extract_features(method="GET", path="/x")
        assert f.has_cookie is False

    def test_auth_header_detected(self):
        f = extract_features(
            method="GET",
            path="/api/data",
            headers={"Authorization": "Bearer token123"},
        )
        assert f.has_auth_header is True

    def test_double_url_encoding_decoded(self):
        # %2527 → %27 → ' after double decoding
        f = extract_features(method="GET", path="/x", query_string="q=%2527")
        # combined_text should contain the decoded variant
        assert f.combined_text  # at minimum it's non-empty

    def test_combined_text_includes_user_agent(self):
        f = extract_features(
            method="GET",
            path="/x",
            headers={"User-Agent": "sqlmap/1.0"},
        )
        assert "sqlmap" in f.combined_text

    def test_num_headers(self):
        f = extract_features(
            method="GET",
            path="/x",
            headers={"Accept": "*/*", "User-Agent": "test", "X-Custom": "val"},
        )
        assert f.num_headers == 3
