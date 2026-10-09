-- STOR-001: proposed Neon/PostgreSQL feature persistence schema.
-- Not applied by this fake-first slice. No TimescaleDB extension is required.
BEGIN;

CREATE TABLE IF NOT EXISTS stor_organizations (
    org_id text PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS stor_datasets (
    org_id text NOT NULL REFERENCES stor_organizations(org_id),
    dataset_id text NOT NULL,
    owner_id text NOT NULL,
    PRIMARY KEY (org_id, dataset_id)
);

CREATE TABLE IF NOT EXISTS stor_instruments (
    org_id text NOT NULL REFERENCES stor_organizations(org_id),
    instrument_id text NOT NULL,
    PRIMARY KEY (org_id, instrument_id)
);

-- Policy rows are separate from datasets. SEC-002 owns the API authorization decision.
CREATE TABLE IF NOT EXISTS stor_dataset_access_policies (
    org_id text NOT NULL,
    dataset_id text NOT NULL,
    policy_id text NOT NULL,
    subject_type text NOT NULL CHECK (subject_type IN ('org', 'user', 'service', 'role')),
    subject_id text NOT NULL,
    permissions text[] NOT NULL,
    PRIMARY KEY (org_id, dataset_id, policy_id),
    FOREIGN KEY (org_id, dataset_id) REFERENCES stor_datasets(org_id, dataset_id)
);

CREATE TABLE IF NOT EXISTS stor_feature_definitions (
    org_id text NOT NULL,
    dataset_id text NOT NULL,
    feature_name text NOT NULL,
    PRIMARY KEY (org_id, dataset_id, feature_name),
    FOREIGN KEY (org_id, dataset_id) REFERENCES stor_datasets(org_id, dataset_id)
);

CREATE TABLE IF NOT EXISTS stor_feature_versions (
    org_id text NOT NULL,
    dataset_id text NOT NULL,
    feature_name text NOT NULL,
    feature_version text NOT NULL,
    value_kind text NOT NULL CHECK (value_kind IN ('decimal', 'vector')),
    published boolean NOT NULL,
    definition_sha256 char(64) NOT NULL,
    git_ref text NOT NULL,
    data_interval_start_ns bigint NOT NULL,
    data_interval_end_ns bigint NOT NULL,
    PRIMARY KEY (org_id, dataset_id, feature_name, feature_version),
    FOREIGN KEY (org_id, dataset_id, feature_name)
        REFERENCES stor_feature_definitions(org_id, dataset_id, feature_name),
    CHECK (data_interval_start_ns >= 0),
    CHECK (data_interval_end_ns >= data_interval_start_ns)
);

-- An activated version cannot be rewritten or removed. Deprecation requires a
-- separately reviewed status migration; this schema has only a published flag.
CREATE OR REPLACE FUNCTION stor_reject_published_version_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.published THEN
        RAISE EXCEPTION 'PUBLISHED_VERSION_IMMUTABLE' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS stor_published_version_update_guard ON stor_feature_versions;
CREATE TRIGGER stor_published_version_update_guard
    BEFORE UPDATE ON stor_feature_versions
    FOR EACH ROW EXECUTE FUNCTION stor_reject_published_version_mutation();
DROP TRIGGER IF EXISTS stor_published_version_delete_guard ON stor_feature_versions;
CREATE TRIGGER stor_published_version_delete_guard
    BEFORE DELETE ON stor_feature_versions
    FOR EACH ROW EXECUTE FUNCTION stor_reject_published_version_mutation();

CREATE TABLE IF NOT EXISTS stor_feature_values (
    org_id text NOT NULL,
    dataset_id text NOT NULL,
    feature_name text NOT NULL,
    feature_version text NOT NULL,
    instrument_id text NOT NULL,
    source_dataset_id text NOT NULL,
    source_record_key text NOT NULL,
    event_time_ns bigint NOT NULL,
    availability_ns bigint NOT NULL,
    value_decimal_text text,
    value_vector_json text,
    quality text,
    is_null boolean NOT NULL,
    local_receipt_ns bigint,
    observation_sha256 char(64) NOT NULL,
    PRIMARY KEY (
        org_id, dataset_id, feature_name, feature_version,
        instrument_id, source_dataset_id, source_record_key
    ),
    FOREIGN KEY (org_id, dataset_id, feature_name, feature_version)
        REFERENCES stor_feature_versions(org_id, dataset_id, feature_name, feature_version),
    FOREIGN KEY (org_id, instrument_id)
        REFERENCES stor_instruments(org_id, instrument_id),
    FOREIGN KEY (org_id, source_dataset_id)
        REFERENCES stor_datasets(org_id, dataset_id),
    CHECK (event_time_ns >= 0),
    CHECK (availability_ns >= event_time_ns),
    CHECK (
        (is_null AND value_decimal_text IS NULL AND value_vector_json IS NULL)
        OR
        (NOT is_null AND num_nonnulls(value_decimal_text, value_vector_json) = 1)
    )
);

CREATE INDEX IF NOT EXISTS stor_feature_values_asof_idx
    ON stor_feature_values (
        org_id, dataset_id, feature_name, feature_version, instrument_id,
        availability_ns DESC, event_time_ns DESC, source_record_key DESC
    );

CREATE INDEX IF NOT EXISTS stor_feature_values_time_range_idx
    ON stor_feature_values (
        org_id, dataset_id, feature_name, feature_version, instrument_id,
        event_time_ns, availability_ns
    );

CREATE TABLE IF NOT EXISTS stor_feature_lineage (
    org_id text NOT NULL,
    dataset_id text NOT NULL,
    feature_name text NOT NULL,
    feature_version text NOT NULL,
    upstream_dataset_id text NOT NULL,
    job_id text NOT NULL,
    run_id text NOT NULL,
    PRIMARY KEY (
        org_id, dataset_id, feature_name, feature_version,
        upstream_dataset_id, job_id, run_id
    ),
    FOREIGN KEY (org_id, dataset_id, feature_name, feature_version)
        REFERENCES stor_feature_versions(org_id, dataset_id, feature_name, feature_version),
    FOREIGN KEY (org_id, upstream_dataset_id)
        REFERENCES stor_datasets(org_id, dataset_id)
);

COMMIT;
