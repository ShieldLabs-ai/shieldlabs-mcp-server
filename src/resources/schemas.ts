import { z } from 'zod';
import { IdentificationOutputSchema } from '../identification.js';
import wireWebhookSchema from './wire/webhook-event.schema.json';

/** Same public schema as tool structuredContent. Raw upstream fields are never exposed. */
export const IDENTIFICATION_SCHEMA = {
  ...z.toJSONSchema(IdentificationOutputSchema),
  $id: 'shieldlabs://contract/identification',
  title: 'ShieldLabs MCP identification projection',
  description:
    '20 detection flags (null when unavailable) and optional bounded HRE/client identity. The wire identifier identification_id is exposed as request_id for MCP compatibility.',
};

/** Public wire schema, pinned to shieldlabs-openapi 8af12c0. MCP outputs use request_id, wire uses identification_id. */
export const WEBHOOK_EVENT_SCHEMA = wireWebhookSchema;
