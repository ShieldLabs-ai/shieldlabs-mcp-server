export const MOCK_DOMAIN_ID = '11111111-1111-4111-8111-111111111111';
/** Fixture adapter only: production never normalizes entity cards through legacy rows. */
export function mockEntity(row, domain = 'example.com') {
  const score = Number(row.score);
  const valid = Number.isInteger(score) && score >= 0 && score <= 100;
  const at = new Date(
    String(row.created_at).replace(' ', 'T') + (String(row.created_at).includes('Z') ? '' : 'Z'),
  );
  const stamp = Number.isFinite(at.getTime()) ? at.toISOString() : '2026-10-28T12:00:00Z';
  return {
    type: 'identification',
    id: String(row.identification_id || row.request_id),
    domain_id: MOCK_DOMAIN_ID,
    domain,
    created_at: stamp,
    risk: valid
      ? {
          state: 'ok',
          band: score < 30 ? 'trusted' : score < 60 ? 'suspicious' : 'dangerous',
          score,
          as_of: stamp,
        }
      : { state: 'unavailable', band: null, as_of: null },
    signals: { state: 'unavailable', items: [] },
    visitor_id: row.visitor_id ?? null,
    user_hid: row.user_hid ?? null,
    device_id: row.device_id ?? null,
    browser: row.browser ?? null,
  };
}
export function entityReply(rows, resource, id, search, domain = 'example.com') {
  let data = rows.map((row) => mockEntity(row, domain));
  if (id !== undefined) {
    if (resource === 'identifications') {
      const card = data.find((v) => v.id === id);
      return card
        ? { status: 200, body: { data: card } }
        : { status: 404, body: { error: { code: 'not_found' } } };
    }
    const matches = rows.filter(
      (row) =>
        String(
          row[{ user: 'user_hid', visitor: 'visitor_id', device: 'device_id', ip: 'ip' }[resource]],
        ) === id,
    );
    if (!matches.length) return { status: 404, body: { error: { code: 'not_found' } } };
    return {
      status: 200,
      body: {
        data: {
          ...mockEntity(matches[0], domain),
          type: resource,
          id,
          identifications: matches.length,
        },
      },
    };
  }
  if (resource === 'user') {
    const users = [...new Set(rows.map((r) => r.user_hid).filter((v) => v && v !== 'anonymous'))];
    data = users.map((user) => ({
      ...mockEntity(
        rows.find((r) => r.user_hid === user),
        domain,
      ),
      type: 'user',
      id: user,
      identifications: rows.filter((r) => r.user_hid === user).length,
    }));
  }
  const limit = Number(search.get('limit') ?? 20),
    offset = Number(search.get('page_token')?.replace('fixture-', '') ?? 0);
  const slice = data.slice(offset, offset + limit),
    next = offset + slice.length < data.length ? `fixture-${offset + slice.length}` : null;
  return {
    status: 200,
    body: {
      data: slice,
      next_page_token: next,
      ...(search.get('include_total') === 'true' ? { total: data.length } : {}),
    },
  };
}
