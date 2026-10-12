"""Bounded markup inventory, including controls not associated with forms.

HTMLParser does not compute visibility, execute handlers, or load frames/scripts.
"""

from __future__ import annotations

from html.parser import HTMLParser
import re

from .adapters import MAX_ENTRIES, MAX_URL_CHARS, label, origin, origin_url, safe_url
from .semantics import classify
from urllib.parse import urljoin, urlsplit

MAX_DOM_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 256
VOID_TAGS = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"})


class MarkupBudgetExceeded(Exception):
    """Stop parsing before a skipped event can corrupt ancestry or label state."""


def semantic(tag: str, attrs: dict, associated_text: str) -> str:
    kind = attrs.get("type", "text").lower()
    if tag in {"select", "textarea"}:
        return tag
    if kind in {"hidden", "checkbox", "password"}:
        return kind
    auto = attrs.get("autocomplete", "").lower().split()
    words = " ".join(attrs.get(k, "")[:500] for k in
                     ("name", "id", "placeholder", "aria-label")) + " " + associated_text[:1000]
    # CamelCase and underscore identifiers are local hints, never page-wide matches.
    words = re.sub(r"([a-z])([A-Z])", r"\1 \2", words).lower()
    words = re.sub(r"[_-]+", " ", words)
    if any(v in auto for v in {"current-password", "new-password"}) or re.search(r"\bpassword\b", words):
        return "password"
    if "cc-number" in auto or re.search(r"\b(?:card number|cardnumber|pan)\b", words):
        return "pan"
    if any(v in auto for v in {"cc-exp", "cc-exp-month", "cc-exp-year"}) or re.search(r"\b(?:expiry|expiration|card exp|mm / yy)\b", words):
        return "expiry"
    if "cc-csc" in auto or re.search(r"\b(?:cvc|cvv|card security code)\b", words):
        return "cvc"
    if "one-time-code" in auto or re.search(r"\b(?:otp|one time code|verification code|authentication code)\b", words):
        return "otp_candidate"
    if kind == "email" or "email" in auto or re.search(r"\b(?:email|e mail)\b", words):
        return "email"
    if "username" in auto or re.search(r"\b(?:username|user name|loginfmt)\b", words):
        return "username"
    if kind == "tel" or any(v.startswith("tel") for v in auto) or re.search(r"\b(?:phone|telephone)\b", words):
        return "phone"
    if any(v in auto for v in {"name", "given-name", "family-name", "organization", "cc-name"}) or re.search(r"\b(?:first name|last name|full name|billing name|company|contact)\b", words):
        return "name_contact"
    return "generic_text" if kind in {"text", "search", "number", ""} else "other_control"


class MarkupInventory(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self.controls: list[dict] = []
        self.script_refs: list[dict] = []
        self.submits: list[dict] = []
        self.presentation: list[dict] = []
        self.form_stack: list[int] = []
        self.labels: list[dict] = []
        self.stack: list[dict] = []
        self.id_text: dict[str, str] = {}
        self.id_locations: dict[str, dict] = {}
        self.id_counts: dict[str, int] = {}
        self.base_href_present = False
        self.partial = False
        self.budget_reason: str | None = None
        # Ancillary interaction snapshot; exhaustion never changes markup integrity.
        self.interaction_elements: list[dict] = []
        self.interaction_truncated = False

    def _exceed(self, reason: str) -> None:
        self.partial = True
        self.budget_reason = reason
        raise MarkupBudgetExceeded(reason)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.partial:
            raise MarkupBudgetExceeded(self.budget_reason)
        values = {k: v or "" for k, v in attrs}
        location = {"line": self.getpos()[0], "column": self.getpos()[1]}
        is_control = tag in {"input", "select", "textarea"} and values.get("type", "").lower() not in {"submit", "reset", "button", "image"}
        is_submit = (tag == "button" and values.get("type", "submit").lower() not in {"button", "reset"} or
                     tag == "input" and values.get("type", "").lower() in {"submit", "image"})
        is_presentation = tag in {"title", "img", "a", "h1", "h2", "h3", "p", "span", "text"}
        entries = len(self.controls) + len(self.forms) + len(self.script_refs) + len(self.submits) + len(self.presentation)
        new_entries = int(tag == "form") + int(tag == "script" and bool(values.get("src"))) + int(is_control) + int(is_submit) + int(is_presentation)
        # Check every budget before mutating either the general or form stack.
        if entries + new_entries > MAX_ENTRIES:
            self._exceed("entry budget exceeded")
        if tag not in VOID_TAGS and len(self.stack) >= MAX_DEPTH:
            self._exceed("depth budget exceeded")
        if tag == "label" and len(self.labels) >= MAX_ENTRIES:
            self._exceed("label budget exceeded")
        if values.get("id") and values["id"] not in self.id_locations and len(self.id_locations) >= MAX_ENTRIES:
            self._exceed("element ID budget exceeded")
        if values.get("id"):
            self.id_locations[values["id"]] = location
            self.id_counts[values["id"]] = self.id_counts.get(values["id"], 0) + 1
        context = "inert_markup" if any(node["tag"] in {"template", "noscript"} for node in self.stack) else "document_markup"
        if len(self.interaction_elements) < 4096:
            self.interaction_elements.append({"tag": tag, "attrs": values, "location": location,
                "markup_context": context, "ancestors": [n["location"] for n in self.stack]})
        else:
            self.interaction_truncated = True
        if tag == "base" and "href" in values and context == "document_markup":
            self.base_href_present = True
        if tag == "form":
            self.forms.append({"attrs": values, "location": location, "markup_context": context})
            self.form_stack.append(len(self.forms) - 1)
        if tag == "script" and values.get("src"):
            self.script_refs.append({"location": location})  # Source text is not supplied.
        if is_control:
            control = {"attrs": values, "tag": tag, "location": location,
                       "markup_context": context,
                       "ancestor_form": self.form_stack[-1] if self.form_stack else None,
                       "label_refs": [node["label"] for node in self.stack if node.get("label") is not None]}
            self.controls.append(control)
        if is_submit:
            self.submits.append({"attrs": values, "tag": tag, "location": location,
                                 "ancestor_form": self.form_stack[-1] if self.form_stack else None})
        presentation_index = None
        inactive = any(node["tag"] in {"script", "style", "template", "noscript"} for node in self.stack)
        if is_presentation:
            self.presentation.append({"tag": tag, "attrs": values, "location": location,
                                      "text": "", "inactive": inactive,
                                      "svg_title": tag == "title" and any(n["tag"] == "svg" for n in self.stack)})
            presentation_index = len(self.presentation) - 1
        if tag not in VOID_TAGS:
            node = {"tag": tag, "id": values.get("id"), "text": "", "label": None,
                    "presentation": presentation_index, "location": location}
            if tag == "label":
                self.labels.append({"for": values.get("for"), "text": "", "location": location})
                node["label"] = len(self.labels) - 1
            self.stack.append(node)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if self.partial:
            return
        # Only text belonging to associated labels/elements is retained, never scripts.
        if any(node["tag"] in {"script", "style"} for node in self.stack):
            return
        # Presentation text is local to its nearest supported element, never a page bag.
        for node in reversed(self.stack):
            if node.get("presentation") is not None:
                entry = self.presentation[node["presentation"]]
                entry["text"] = (entry["text"] + " " + data)[:1000]
                break
        for node in self.stack:
            if node["id"] or node["label"] is not None:
                node["text"] = (node["text"] + " " + data)[:1000]
                if node["label"] is not None:
                    self.labels[node["label"]]["text"] = node["text"]

    def handle_endtag(self, tag: str) -> None:
        if self.partial:
            return
        if tag == "form" and self.form_stack:
            self.form_stack.pop()
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i]["tag"] == tag:
                for node in self.stack[i:]:
                    if node["id"]:
                        self.id_text[node["id"]] = node["text"]
                del self.stack[i:]
                break

    def inventory(self, document_url: str | None = None) -> dict:
        if self.partial:
            # Earlier controls may depend on later labels or explicit form targets.
            # A partial prefix is not a structurally complete inventory.
            raise MarkupBudgetExceeded(self.budget_reason)
        form_ids: dict[str, list[int]] = {}
        label_text: dict[str, list[dict]] = {}
        for entry in self.labels:
            if entry["for"]:
                label_text.setdefault(entry["for"], []).append(entry)
        for i, form in enumerate(self.forms):
            form_ids.setdefault(form["attrs"].get("id", ""), []).append(i)
        controls = []
        for i, control in enumerate(self.controls):
            attrs = control["attrs"]
            associated = [self.labels[n] for n in control["label_refs"]]
            associated += label_text.get(attrs.get("id"), [])
            local_sources = [{"source": "associated_label", "text": entry["text"], "location": entry["location"]} for entry in associated]
            local_sources += [{"source": "aria-labelledby", "attribute": "aria-labelledby", "text": self.id_text.get(name, ""),
                               "location": self.id_locations.get(name)}
                              for name in attrs.get("aria-labelledby", "").split()[:MAX_ENTRIES]]
            role, support = classify(control["tag"], attrs, local_sources)
            form_index, association = self._association(control, form_ids)
            html_type = attrs.get("type", "text").lower() if control["tag"] == "input" else None
            controls.append({
                "index": i, "tag": control["tag"], "semantic_type": semantic(control["tag"], attrs, " ".join(e["text"] for e in local_sources)),
                "structural_control": control["tag"], "html_type": label(html_type),
                "markup_context": control["markup_context"],
                "control_kind": html_type if html_type in {"hidden", "checkbox", "radio"} else control["tag"],
                "semantic_role": role, "semantic_support": support,
                "supporting_hints": {k: label(attrs.get(k)) for k in ("inputmode", "pattern", "maxlength") if k in attrs},
                "name": label(attrs.get("name")), "element_id": label(attrs.get("id")),
                "input_type": label(attrs.get("type", "text") if control["tag"] == "input" else control["tag"]),
                "autocomplete": label(attrs.get("autocomplete")), "form_index": form_index,
                "form_association": association, "location": control["location"],
                "markup_hidden": "hidden" in attrs, "aria_hidden": attrs.get("aria-hidden") == "true",
                "disabled": "disabled" in attrs, "visibility": "unresolved", "submission": "not_evaluated",
                "value_present_in_markup": "value" in attrs,
            })
        forms = []
        for index, form in enumerate(self.forms):
            attrs = form["attrs"]
            method, basis = self._method(attrs.get("method"))
            target = self._target(attrs.get("action"), document_url) if method != "DIALOG" else None
            submits = []
            for submit in self.submits:
                owner, association = self._association(submit, form_ids)
                if owner != index:
                    continue
                override_method = submit["attrs"].get("formmethod")
                override_action = submit["attrs"].get("formaction")
                submits.append({"tag": submit["tag"], "location": submit["location"],
                                "element_id": label(submit["attrs"].get("id")), "association": association,
                                "formmethod": self._method(override_method)[0] if override_method is not None else None,
                                "formaction": safe_url(override_action),
                                "resolved_formaction": safe_url(self._target(override_action, document_url)) if override_action is not None else None})
            forms.append({"index": index, "element_id": label(attrs.get("id")), "location": form["location"],
                          "markup_context": form["markup_context"],
                          "markup_method": method, "method_basis": basis, "markup_action": safe_url(attrs.get("action")),
                          "resolved_markup_target": safe_url(target), "target_basis": "current_document" if not attrs.get("action") else "markup_action",
                          "target_origin": origin_url(target),
                          "target_resolution": "resolved" if target else "unresolved",
                          "control_indices": [c["index"] for c in controls if c["form_index"] == index],
                          "submit_controls": submits, "runtime_submission": "not_established"})
        return {"forms_count": len(self.forms), "controls_count": len(controls), "controls": controls,
                "forms": forms, "external_script_references": len(self.script_refs)}

    @staticmethod
    def _association(control: dict, form_ids: dict) -> tuple[int | None, str]:
        attrs = control["attrs"]
        if "form" in attrs:
            matches = form_ids.get(attrs["form"], []) if attrs["form"] else []
            return (matches[0], "explicit") if len(matches) == 1 else (None, "unresolved")
        owner = control["ancestor_form"]
        return owner, "ancestor" if owner is not None else "none"

    @staticmethod
    def _method(value: str | None) -> tuple[str, str]:
        if value is None or not value:
            return "GET", "html_default"
        method = value.lower()
        return (method.upper(), "attribute") if method in {"get", "post", "dialog"} else ("GET", "invalid_attribute_html_default")

    def _target(self, action: str | None, document_url: str | None) -> str | None:
        if action is not None and len(action) > MAX_URL_CHARS or document_url is not None and len(document_url) > MAX_URL_CHARS:
            return None
        if action and self.base_href_present:
            try:
                if not urlsplit(action).scheme:
                    return None  # No guessed target when document-relative resolution is affected by <base>.
            except ValueError:
                return None
        if not isinstance(document_url, str) or origin(document_url) is None:
            # An absolute action can still be resolved without a document URL.
            return action if origin(action) is not None else None
        try:
            target = urljoin(document_url, action or document_url)
            return target if origin(target) is not None else None
        except ValueError:
            return None
