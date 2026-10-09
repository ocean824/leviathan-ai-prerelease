"""Checksum-verified import of only the deterministic EA-002 generated schema."""

from __future__ import annotations

import base64
import io
import json
import zipfile
from hashlib import sha256
from typing import Any, NoReturn

from leviathan_core.ea_builder.export_source import (
    MAX_ARCHIVE_BYTES,
    SourceExportError,
    SourcePackageV1,
    ValidatedGraphV1,
    _archive,
    _canonical_catalog_json,
    _canonical_graph_json,
    _generate_source_package,
    _load_catalog_json,
    _load_graph_json,
    _params_hash,
    _parse_spec,
    _parse_templates,
)
from leviathan_core.ea_builder.graph import GraphV1, TargetV1
from leviathan_core.ea_builder.validate import validate
from leviathan_core.numeric import canonical_json
from leviathan_core.seal import Issuer, SealedModel, require

_ISSUED_ROUNDTRIP = Issuer("ea002.roundtrip")


class RoundTripV1(SealedModel):
    graph_json: str
    graph_hash: str
    params_hash: str
    build_id: str
    source_text: str
    manifest_json: str

    @property
    def graph(self) -> GraphV1:
        require(self, _ISSUED_ROUNDTRIP.tag)
        return _load_graph_json(self.graph_json)


def _invalid(field: str) -> NoReturn:
    raise SourceExportError("PACKAGE_INVALID", field)


def _canonical_document(content: bytes, field: str) -> Any:
    try:
        parsed = json.loads(content)
        if canonical_json(parsed) != content:
            _invalid(field)
        return parsed
    except SourceExportError:
        raise
    except Exception:
        _invalid(field)


def import_generated_package(package: SourcePackageV1 | bytes) -> RoundTripV1:
    """Verify checksums and regenerate every archive byte before reconstruction."""
    if type(package) is SourcePackageV1:
        require(package, "ea002.source_package")
        archive = package.archive_bytes
    elif type(package) is bytes:
        archive = package
    else:
        _invalid("archive")
    if not archive or len(archive) > MAX_ARCHIVE_BYTES:
        _invalid("archive")
    try:
        with zipfile.ZipFile(io.BytesIO(archive), "r") as handle:
            infos = handle.infolist()
            names = [item.filename for item in infos]
            suffixes = [name for name in names if name in ("source.mq4", "source.mq5")]
            if len(suffixes) != 1:
                _invalid("archive")
            expected = {
                suffixes[0],
                "manifest.json",
                "parameter-map.json",
                "provenance.txt",
                "dependencies.json",
                "graph.json",
                "catalog.json",
                "export-spec.json",
                "templates.json",
                "README.txt",
                "checksums.json",
            }
            if len(infos) != len(expected) or set(names) != expected or names != sorted(names):
                _invalid("archive")
            if any(
                item.file_size > MAX_ARCHIVE_BYTES
                or item.compress_type != zipfile.ZIP_STORED
                or item.flag_bits != 0
                or item.date_time != (1980, 1, 1, 0, 0, 0)
                for item in infos
            ):
                _invalid("archive")
            files = {name: handle.read(name) for name in names}
    except SourceExportError:
        raise
    except Exception:
        _invalid("archive")
    checksums = _canonical_document(files["checksums.json"], "checksums")
    expected_checksums = {
        name: sha256(content).hexdigest()
        for name, content in files.items()
        if name != "checksums.json"
    }
    if checksums != expected_checksums:
        _invalid("checksums")
    # Canonical ZIP metadata is part of the schema, not merely the file contents.
    if _archive(files) != archive:
        _invalid("archive")
    try:
        graph = _load_graph_json(files["graph.json"])
        catalog = _load_catalog_json(files["catalog.json"])
        spec = _parse_spec(_canonical_document(files["export-spec.json"], "export-spec"))
        templates = _parse_templates(_canonical_document(files["templates.json"], "templates"))
        _canonical_document(files["manifest.json"], "manifest")
        _canonical_document(files["parameter-map.json"], "parameter-map")
        if files["dependencies.json"] != b"[]":
            _invalid("dependencies")
        graph_json = _canonical_graph_json(graph)
        catalog_json = _canonical_catalog_json(catalog)
        target = TargetV1(platform=spec.platform)
        validation = validate(graph, catalog, target)
        if validation.status != "VALID":
            _invalid("graph")
        validated = ValidatedGraphV1(
            graph_json=graph_json,
            catalog_json=catalog_json,
            target_platform=target.platform,
            validation_json=canonical_json(validation.model_dump(mode="json")).decode("ascii"),
            graph_hash=sha256(graph_json.encode("ascii")).hexdigest(),
            params_hash=_params_hash(graph),
        )
        # This private renderer reconstructs and compares archive content only;
        # it does not issue the imported graph or a new export capability.
        regenerated = _generate_source_package(validated, spec, templates)
        if base64.b64decode(regenerated.archive_b64, validate=True) != archive:
            _invalid("archive")
        result = RoundTripV1(
            graph_json=validated.graph_json,
            graph_hash=regenerated.graph_hash,
            params_hash=regenerated.params_hash,
            build_id=regenerated.build_id,
            source_text=regenerated.source_text,
            manifest_json=regenerated.manifest_json,
        )
        return _ISSUED_ROUNDTRIP.issue(result)
    except SourceExportError:
        raise
    except Exception:
        _invalid("archive")
