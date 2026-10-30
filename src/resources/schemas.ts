import { z } from 'zod';
import { IdentificationOutputSchema } from '../identification.js';
import wireWebhookSchema from './wire/webhook-event.schema.json';

/** Same public schema as tool structuredContent. Raw upstream fields are never exposed. */
export const IDENTIFICATION_SCHEMA = {
  ...z.toJSONSchema(IdentificationOutputSchema),
  $id: 'shieldlabs://contract/identification',
  title: 'ShieldLabs MCP identification projection',
  description:
    '20 detection flags (null when unavailable) and optional bounded HRE/client identity. The identifier is identification_id, the same field as the webhook.',
};

/** Public wire schema, pinned to shieldlabs-openapi ea1898a. MCP outputs use identification_id, matching the webhook. */
export const WEBHOOK_EVENT_SCHEMA = wireWebhookSchema;
