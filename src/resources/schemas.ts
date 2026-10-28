import { z } from 'zod';
import { IdentificationOutputSchema } from '../identification.js';
import wireWebhookSchema from './wire/webhook-event.schema.json';

/** Same public schema as tool structuredContent. Raw upstream fields are never exposed. */
export const IDENTIFICATION_SCHEMA = {
  ...z.toJSONSchema(IdentificationOutputSchema),
  $id: 'shieldlabs://contract/identification',
  title: 'ShieldLabs MCP identification projection',
  description:
    '20 current flags (null when unavailable), six legacy compatibility flags, and optional bounded HRE/client identity. The wire identifier identification_id is exposed as request_id for MCP compatibility.',
};

/** Public wire schema, pinned to shieldlabs-openapi 3fc61ef. MCP outputs use request_id, wire uses identification_id. */
export const WEBHOOK_EVENT_SCHEMA = wireWebhookSchema;
