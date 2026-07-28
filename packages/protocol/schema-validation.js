import fs from "node:fs";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const SCHEMA_DIRECTORY = fileURLToPath(
  new URL("../../schemas/", import.meta.url)
);
const validators = new Map();
let catalog = null;

function schemaFile(name) {
  if (!/^[a-z0-9-]+$/.test(name)) {
    throw new TypeError("Schema name is invalid.");
  }
  return `${SCHEMA_DIRECTORY}${name}.schema.json`;
}

function validator(name) {
  if (validators.has(name)) return validators.get(name);
  if (!catalog) {
    catalog = new Ajv2020({
      allErrors: true,
      strict: true,
      allowUnionTypes: true
    });
    addFormats(catalog);
    for (const file of fs.readdirSync(SCHEMA_DIRECTORY)) {
      if (!file.endsWith(".schema.json")) continue;
      catalog.addSchema(
        JSON.parse(
          fs.readFileSync(`${SCHEMA_DIRECTORY}${file}`, "utf8")
        )
      );
    }
  }
  const schema = JSON.parse(fs.readFileSync(schemaFile(name), "utf8"));
  const compiled = catalog.getSchema(schema.$id);
  validators.set(name, compiled);
  return compiled;
}

export function validateArtifactSchema(name, value) {
  const validate = validator(name);
  if (validate(value)) {
    return { valid: true, schema: name };
  }
  return {
    valid: false,
    schema: name,
    reason: "Artifact failed schema validation.",
    errors: validate.errors?.map((error) => ({
      instancePath: error.instancePath,
      keyword: error.keyword,
      message: error.message
    })) ?? []
  };
}

export function assertArtifactSchema(name, value) {
  const result = validateArtifactSchema(name, value);
  if (!result.valid) {
    throw new Error(
      `${result.reason} ${result.errors
        .map((error) => `${error.instancePath || "/"} ${error.message}`)
        .join("; ")}`
    );
  }
  return value;
}
