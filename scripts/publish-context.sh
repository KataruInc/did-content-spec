#!/usr/bin/env sh
# SPDX-License-Identifier: MIT
# Publish the JSON-LD context and JSON Schema to the did.kataru.io S3 bucket.
#
#   AWS_PROFILE=<profile> sh scripts/publish-context.sh
#
# Objects are uploaded with a long cache lifetime because context URLs are
# versioned (…/v1); publish a new path, never overwrite, for breaking changes.
set -eu

BUCKET="${DID_CONTENT_BUCKET:-did.kataru.io}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

aws s3 cp "$ROOT/contexts/did-content-v1.jsonld" "s3://$BUCKET/did-content/v1" \
  --content-type "application/ld+json" \
  --cache-control "public, max-age=31536000, immutable"

aws s3 cp "$ROOT/schemas/log-entry.schema.json" "s3://$BUCKET/did-content/schemas/log-entry.schema.json" \
  --content-type "application/schema+json" \
  --cache-control "public, max-age=86400"

echo "published:"
echo "  https://$BUCKET/did-content/v1"
echo "  https://$BUCKET/did-content/schemas/log-entry.schema.json"
