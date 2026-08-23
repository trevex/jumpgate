-- +goose Up
CREATE TABLE role_capabilities (
    role_id   uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    scope     text NOT NULL,
    action    text NOT NULL,
    qualifier text NOT NULL,
    PRIMARY KEY (role_id, scope, action, qualifier)
);
CREATE INDEX idx_role_capabilities_match ON role_capabilities (scope, action, qualifier);

-- +goose StatementBegin
CREATE FUNCTION authz_normalize_cap(pat text, OUT scope text, OUT action text, OUT qualifier text) AS $$
DECLARE segs text[] := string_to_array(pat, ':'); col text[] := ARRAY['','','']; star bool := false; seg text;
BEGIN
    FOR i IN 1..3 LOOP
        IF star THEN col[i] := '*';
        ELSIF i > COALESCE(array_length(segs,1),0) THEN col[i] := '';
        ELSE
            seg := segs[i];
            IF seg = '**' THEN col[i] := '*'; star := true;
            ELSE col[i] := seg; END IF;
        END IF;
    END LOOP;
    scope := col[1]; action := col[2]; qualifier := col[3];
END;
$$ LANGUAGE plpgsql IMMUTABLE;
-- +goose StatementEnd

INSERT INTO role_capabilities (role_id, scope, action, qualifier)
SELECT r.id, n.scope, n.action, n.qualifier
FROM roles r
CROSS JOIN LATERAL jsonb_array_elements_text(r.capabilities) AS pat
CROSS JOIN LATERAL authz_normalize_cap(pat) AS n
ON CONFLICT DO NOTHING;

DROP FUNCTION authz_normalize_cap(text);
ALTER TABLE roles DROP COLUMN capabilities;

-- +goose Down
ALTER TABLE roles ADD COLUMN capabilities jsonb NOT NULL DEFAULT '[]'::jsonb;
DROP TABLE role_capabilities;
